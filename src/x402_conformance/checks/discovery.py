"""DI: discovery / Bazaar checks (catalog section 7).

The Discovery API lets clients find x402 resources: ``GET /discovery/resources``
returns ``{x402Version, items[], pagination}`` where each item is a discovered
resource (``resource``, ``type``, ``x402Version``, ``accepts[]``, ``lastUpdated``).
See CORE sections 8.1 and 8.3.

DI-001 and DI-002 only query the operator-supplied Bazaar. DI-003 additionally
cross-fetches URLs supplied by that Bazaar. Those cross-fetches use a dedicated,
DNS-pinning client and reject non-public destinations unless the operator supplied
an explicit host or network allowlist.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import math
import re
import socket
import ssl
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, TypeGuard
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from .. import USER_AGENT
from .base import CheckResult, Severity, Status, append_unique_check

_CORE = "x402-specification-v2.md"
_CAIP2 = re.compile(r"^[a-z0-9-]{3,8}:[-_a-zA-Z0-9]{1,32}$")
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_MAX_REDIRECTS = 3
_MAX_CROSS_FETCH_REQUESTS = 10
_MAX_CROSS_FETCH_REQUESTS_PER_HOST = 5
_MAX_CROSS_FETCH_BYTES = 2 * 1024 * 1024

IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
AddressResolver = Callable[[str, int], Iterable[str]]


class CrossFetchError(RuntimeError):
    """A DI-003 resource cannot be fetched safely or reliably."""


@dataclass(frozen=True)
class _CrossFetchAllowlist:
    hosts: frozenset[str] = frozenset()
    networks: tuple[IpNetwork, ...] = ()

    @classmethod
    def parse(cls, entries: Sequence[str]) -> _CrossFetchAllowlist:
        hosts: set[str] = set()
        networks: list[IpNetwork] = []
        for raw_entry in entries:
            entry = raw_entry.strip()
            if not entry:
                raise ValueError("cross-fetch allowlist entries must not be empty")
            try:
                networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                if "/" in entry or "*" in entry or "://" in entry:
                    raise ValueError(
                        f"invalid cross-fetch allowlist entry: {raw_entry!r}; "
                        "use an exact hostname, IP address, or CIDR"
                    ) from None
                hosts.add(_canonical_host(entry))
        return cls(frozenset(hosts), tuple(networks))

    def permits(self, host: str, address: IpAddress) -> bool:
        if _canonical_host(host) in self.hosts:
            return True
        return any(address in network for network in self.networks)


@dataclass(frozen=True)
class _ValidatedTarget:
    url: str
    scheme: str
    host: str
    port: int
    request_target: str
    host_header: str
    addresses: tuple[IpAddress, ...]


def _canonical_host(host: str) -> str:
    value = host.rstrip(".").lower()
    if not value or "%" in value:
        raise ValueError(f"invalid hostname: {host!r}")
    try:
        return value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"invalid hostname: {host!r}") from exc


def _system_resolver(host: str, port: int) -> Iterable[str]:
    for _family, _socktype, _proto, _canonname, sockaddr in socket.getaddrinfo(
        host, port, type=socket.SOCK_STREAM
    ):
        yield str(sockaddr[0])


def _resolve_addresses(host: str, port: int, resolver: AddressResolver) -> tuple[IpAddress, ...]:
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        try:
            raw_addresses = resolver(host, port)
            addresses = tuple(dict.fromkeys(ipaddress.ip_address(value) for value in raw_addresses))
        except (OSError, ValueError) as exc:
            raise CrossFetchError(f"DNS resolution failed for {host}: {exc}") from exc
    else:
        addresses = (literal,)
    if not addresses:
        raise CrossFetchError(f"DNS resolution returned no addresses for {host}")
    return addresses


def _is_public_address(address: IpAddress) -> bool:
    # Python deliberately reports some multicast ranges as globally scoped, so
    # check every forbidden class explicitly instead of relying on ``is_global``.
    return address.is_global and not (
        address.is_loopback
        or address.is_private
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def _format_host_header(host: str, port: int, scheme: str) -> str:
    display_host = f"[{host}]" if ":" in host else host
    default_port = 443 if scheme == "https" else 80
    return display_host if port == default_port else f"{display_host}:{port}"


def _validate_cross_fetch_target(
    url: str,
    *,
    resolver: AddressResolver,
    allowlist: _CrossFetchAllowlist,
) -> _ValidatedTarget:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise CrossFetchError(f"invalid resource URL: {exc}") from exc
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise CrossFetchError("resource URL must use http or https")
    if parsed.username is not None or parsed.password is not None:
        raise CrossFetchError("resource URL must not contain userinfo")
    if parsed.hostname is None:
        raise CrossFetchError("resource URL is missing a host")
    try:
        host = _canonical_host(parsed.hostname)
    except ValueError as exc:
        raise CrossFetchError(str(exc)) from exc
    if port is None:
        port = 443 if scheme == "https" else 80
    if not 1 <= port <= 65535:
        raise CrossFetchError("resource URL port is outside 1..65535")

    addresses = _resolve_addresses(host, port, resolver)
    denied = [
        address
        for address in addresses
        if not _is_public_address(address) and not allowlist.permits(host, address)
    ]
    if denied:
        rendered = ", ".join(str(address) for address in denied)
        raise CrossFetchError(f"resource host resolves to a non-public address ({rendered})")

    path = parsed.path or "/"
    request_target = f"{path}?{parsed.query}" if parsed.query else path
    return _ValidatedTarget(
        url=urlunsplit((scheme, parsed.netloc, parsed.path, parsed.query, "")),
        scheme=scheme,
        host=host,
        port=port,
        request_target=request_target,
        host_header=_format_host_header(host, port, scheme),
        addresses=addresses,
    )


def _display_url(url: str) -> str:
    """Render a resource URL without userinfo, query parameters, or fragments."""
    try:
        parsed = urlsplit(url)
        host = parsed.hostname or "<invalid-host>"
        if ":" in host:
            host = f"[{host}]"
        port = parsed.port
        if port is not None:
            host = f"{host}:{port}"
        return urlunsplit((parsed.scheme, host, parsed.path, "", ""))
    except ValueError:
        return "<invalid-resource-url>"


@dataclass
class _SafeCrossFetcher:
    timeout: float
    resolver: AddressResolver
    allowlist: _CrossFetchAllowlist
    # A caller-supplied transport is a test seam. Production cross-fetches use
    # ``_request_pinned`` so the validated DNS answer is the actual peer address.
    test_client: httpx.Client | None = None
    total_requests: int = 0
    requests_per_host: Counter[str] = field(default_factory=Counter)

    def __call__(self, url: str) -> httpx.Response:
        current_url = url
        previous_scheme: str | None = None
        for redirect_count in range(_MAX_REDIRECTS + 1):
            target = _validate_cross_fetch_target(
                current_url, resolver=self.resolver, allowlist=self.allowlist
            )
            if previous_scheme == "https" and target.scheme != "https":
                raise CrossFetchError("HTTPS-to-HTTP redirect is not allowed")
            self._reserve_request(target.host)
            response = self._request(target)
            if response.status_code not in _REDIRECT_STATUSES:
                return response
            location = response.headers.get("location")
            if not location:
                raise CrossFetchError("redirect response is missing Location")
            if redirect_count == _MAX_REDIRECTS:
                raise CrossFetchError(f"more than {_MAX_REDIRECTS} redirects")
            previous_scheme = target.scheme
            current_url = urljoin(target.url, location)
        raise AssertionError("redirect loop bound is unreachable")

    def _reserve_request(self, host: str) -> None:
        if self.total_requests >= _MAX_CROSS_FETCH_REQUESTS:
            raise CrossFetchError("cross-fetch total request cap reached")
        if self.requests_per_host[host] >= _MAX_CROSS_FETCH_REQUESTS_PER_HOST:
            raise CrossFetchError(f"cross-fetch per-host request cap reached for {host}")
        self.total_requests += 1
        self.requests_per_host[host] += 1

    def _request(self, target: _ValidatedTarget) -> httpx.Response:
        if self.test_client is not None:
            return self.test_client.get(target.url, follow_redirects=False)
        errors: list[str] = []
        for address in target.addresses:
            try:
                return self._request_pinned(target, address)
            except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
                errors.append(f"{address}: {exc}")
        raise CrossFetchError("connection failed: " + "; ".join(errors[:3]))

    def _request_pinned(self, target: _ValidatedTarget, address: IpAddress) -> httpx.Response:
        raw_socket = socket.create_connection((str(address), target.port), timeout=self.timeout)
        connection: http.client.HTTPConnection
        try:
            if target.scheme == "https":
                tls_socket = ssl.create_default_context().wrap_socket(
                    raw_socket, server_hostname=target.host
                )
                connection = http.client.HTTPSConnection(
                    target.host, target.port, timeout=self.timeout
                )
                connection.sock = tls_socket
            else:
                connection = http.client.HTTPConnection(
                    target.host, target.port, timeout=self.timeout
                )
                connection.sock = raw_socket
            try:
                connection.request(
                    "GET",
                    target.request_target,
                    headers={
                        "Host": target.host_header,
                        "User-Agent": USER_AGENT,
                        "Accept": "application/json, */*",
                        "Connection": "close",
                    },
                )
                response = connection.getresponse()
                content = response.read(_MAX_CROSS_FETCH_BYTES + 1)
                if len(content) > _MAX_CROSS_FETCH_BYTES:
                    raise CrossFetchError(
                        f"resource response exceeds {_MAX_CROSS_FETCH_BYTES} bytes"
                    )
                return httpx.Response(
                    response.status,
                    headers=response.getheaders(),
                    content=content,
                    request=httpx.Request("GET", target.url),
                )
            finally:
                connection.close()
        except Exception:
            raw_socket.close()
            raise


@dataclass
class DiscoveryContext:
    base_url: str
    client: httpx.Client
    cross_fetch: Callable[[str], httpx.Response]


DiFunc = Callable[[DiscoveryContext], "tuple[Status, str]"]


@dataclass(frozen=True)
class _DiCheck:
    check_id: str
    title: str
    severity: Severity
    spec_ref: str
    func: DiFunc


DI_REGISTRY: list[_DiCheck] = []


def _register(cid: str, title: str, sev: Severity, ref: str) -> Callable[[DiFunc], DiFunc]:
    def deco(f: DiFunc) -> DiFunc:
        append_unique_check(DI_REGISTRY, _DiCheck(cid, title, sev, ref, f), cid)
        return f

    return deco


def _resources_url(base: str) -> str:
    return f"{base.rstrip('/')}/discovery/resources"


def _get_json(
    ctx: DiscoveryContext, url: str, params: dict[str, Any] | None = None
) -> dict[str, Any] | None:
    try:
        resp = ctx.client.get(url, params=params)
        if resp.status_code >= 500:
            raise httpx.HTTPStatusError(
                f"discovery endpoint returned HTTP {resp.status_code}",
                request=resp.request,
                response=resp,
            )
        if resp.status_code != 200:
            return None
        data: Any = json.loads(resp.text)
        return data if isinstance(data, dict) else None
    except httpx.HTTPError:
        raise
    except (ValueError, TypeError):
        return None


def _is_int(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_finite_number(value: object) -> TypeGuard[int | float]:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _validate_requirement(value: object, path: str) -> list[str]:
    if not isinstance(value, dict):
        return [f"{path} not an object"]
    problems: list[str] = []
    for key in ("scheme", "network", "amount", "asset", "payTo"):
        if not isinstance(value.get(key), str) or not value[key]:
            problems.append(f"{path}.{key} missing or not a non-empty string")
    network = value.get("network")
    if isinstance(network, str) and network and _CAIP2.fullmatch(network) is None:
        problems.append(f"{path}.network is not a CAIP-2 identifier")
    timeout = value.get("maxTimeoutSeconds")
    if not _is_finite_number(timeout) or timeout <= 0:
        problems.append(f"{path}.maxTimeoutSeconds must be a positive finite number")
    if "extra" in value and not isinstance(value["extra"], dict):
        problems.append(f"{path}.extra must be an object when present")
    return problems


def _validate_discovery_body(
    body: dict[str, Any],
    *,
    expected_limit: int | None = None,
    expected_offset: int | None = None,
) -> list[str]:
    problems: list[str] = []
    if not _is_int(body.get("x402Version")) or body["x402Version"] != 2:
        problems.append("x402Version must be the integer 2")
    items = body.get("items")
    if not isinstance(items, list):
        problems.append("`items` missing or not an array")
        items = []
    pagination = body.get("pagination")
    if not isinstance(pagination, dict):
        problems.append("`pagination` missing or not an object")
        pagination = {}

    limit = pagination.get("limit")
    offset = pagination.get("offset")
    total = pagination.get("total")
    if not _is_int(limit) or not 1 <= limit <= 100:
        problems.append("pagination.limit must be an integer in 1..100")
    if not _is_int(offset) or offset < 0:
        problems.append("pagination.offset must be a non-negative integer")
    if not _is_int(total) or total < 0:
        problems.append("pagination.total must be a non-negative integer")
    if expected_limit is not None and limit != expected_limit:
        problems.append(f"pagination.limit must echo requested limit={expected_limit}")
    if expected_offset is not None and offset != expected_offset:
        problems.append(f"pagination.offset must echo requested offset={expected_offset}")
    if _is_int(limit) and len(items) > limit:
        problems.append(f"items contains {len(items)} entries but pagination.limit is {limit}")
    if _is_int(total) and _is_int(offset):
        if offset < total and offset + len(items) > total:
            problems.append("pagination offset plus item count exceeds total")
        if offset >= total and items:
            problems.append("pagination returned items at or beyond total")

    for i, item in enumerate(items):
        path = f"items[{i}]"
        if not isinstance(item, dict):
            problems.append(f"{path} not an object")
            continue
        for key in ("resource", "type"):
            if not isinstance(item.get(key), str) or not item[key]:
                problems.append(f"{path}.{key} missing or not a non-empty string")
        version = item.get("x402Version")
        if not _is_int(version) or version < 1:
            problems.append(f"{path}.x402Version must be a positive integer")
        accepts = item.get("accepts")
        if not isinstance(accepts, list) or not accepts:
            problems.append(f"{path}.accepts missing or not a non-empty array")
        else:
            for j, requirement in enumerate(accepts):
                problems.extend(_validate_requirement(requirement, f"{path}.accepts[{j}]"))
        last_updated = item.get("lastUpdated")
        if not _is_finite_number(last_updated) or last_updated < 0:
            problems.append(f"{path}.lastUpdated must be a non-negative finite number")
        if "extensions" in item and not isinstance(item["extensions"], dict):
            problems.append(f"{path}.extensions must be an object when present")
    return problems


@_register(
    "DI-001",
    "/discovery/resources returns schema-valid items + pagination",
    Severity.MAJOR,
    f"{_CORE} sections 8.1, 8.3",
)
def di_001(ctx: DiscoveryContext) -> tuple[Status, str]:
    body = _get_json(ctx, _resources_url(ctx.base_url))
    if body is None:
        return Status.FAIL, "GET /discovery/resources did not return 200 with a JSON object"
    problems = _validate_discovery_body(body, expected_limit=20, expected_offset=0)
    if problems:
        return Status.FAIL, "; ".join(problems[:8])
    return Status.PASS, f"{len(body['items'])} item(s), schema-valid"


def _item_has_accept_value(item: object, key: str, value: str) -> bool:
    if not isinstance(item, dict) or not isinstance(item.get("accepts"), list):
        return False
    return any(
        isinstance(requirement, dict) and requirement.get(key) == value
        for requirement in item["accepts"]
    )


def _first_accept_value(items: list[Any], key: str) -> str | None:
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("accepts"), list):
            continue
        for requirement in item["accepts"]:
            value = requirement.get(key) if isinstance(requirement, dict) else None
            if isinstance(value, str) and value:
                return value
    return None


def _first_item_value(items: list[Any], key: str) -> str | None:
    for item in items:
        value = item.get(key) if isinstance(item, dict) else None
        if isinstance(value, str) and value:
            return value
    return None


def _first_extension(items: list[Any]) -> str | None:
    for item in items:
        extensions = item.get("extensions") if isinstance(item, dict) else None
        if isinstance(extensions, dict) and extensions:
            for key in extensions:
                if isinstance(key, str) and key:
                    return key
    return None


@dataclass(frozen=True)
class _FilterProbe:
    name: str
    value: str
    matches: Callable[[object], bool]
    expect_match: bool = True


def _filter_probes(items: list[Any]) -> list[_FilterProbe]:
    type_value = _first_item_value(items, "type")
    pay_to = _first_accept_value(items, "payTo")
    scheme = _first_accept_value(items, "scheme")
    network = _first_accept_value(items, "network")
    if type_value is None or pay_to is None or scheme is None or network is None:
        return []

    def type_matches(item: object, expected: str = type_value) -> bool:
        return isinstance(item, dict) and item.get("type") == expected

    def pay_to_matches(item: object, expected: str = pay_to) -> bool:
        return _item_has_accept_value(item, "payTo", expected)

    def scheme_matches(item: object, expected: str = scheme) -> bool:
        return _item_has_accept_value(item, "scheme", expected)

    def network_matches(item: object, expected: str = network) -> bool:
        return _item_has_accept_value(item, "network", expected)

    extension = _first_extension(items)
    probes = [
        _FilterProbe("type", type_value, type_matches),
        _FilterProbe("payTo", pay_to, pay_to_matches),
        _FilterProbe("scheme", scheme, scheme_matches),
        _FilterProbe("network", network, network_matches),
    ]
    if extension is None:
        extension = "__x402_conformance_missing_extension__"
        probes.append(_FilterProbe("extensions", extension, lambda _item: False, False))
    else:

        def extension_matches(item: object, expected: str = extension) -> bool:
            return (
                isinstance(item, dict)
                and isinstance(item.get("extensions"), dict)
                and expected in item["extensions"]
            )

        probes.append(_FilterProbe("extensions", extension, extension_matches))
    return probes


@_register(
    "DI-002",
    "Discovery filters and offset pagination are honored",
    Severity.MINOR,
    f"{_CORE} section 8.1",
)
def di_002(ctx: DiscoveryContext) -> tuple[Status, str]:
    url = _resources_url(ctx.base_url)
    body = _get_json(ctx, url)
    if body is None or not isinstance(body.get("items"), list) or not body["items"]:
        return Status.SKIP, "no discoverable items to filter"
    base_problems = _validate_discovery_body(body, expected_limit=20, expected_offset=0)
    if base_problems:
        return Status.FAIL, "unfiltered discovery response is invalid: " + "; ".join(
            base_problems[:4]
        )
    items: list[Any] = body["items"]
    probes = _filter_probes(items)
    if not probes:
        return Status.FAIL, "catalogue has no complete type/payTo/scheme/network filter seed"

    for probe in probes:
        filtered = _get_json(
            ctx,
            url,
            params={probe.name: probe.value, "limit": 100, "offset": 0},
        )
        if filtered is None:
            return Status.FAIL, f"filter {probe.name} did not return 200 with a JSON object"
        problems = _validate_discovery_body(filtered, expected_limit=100, expected_offset=0)
        if problems:
            return Status.FAIL, f"filter {probe.name} returned invalid data: {problems[0]}"
        filtered_items: list[Any] = filtered["items"]
        offenders = [item for item in filtered_items if not probe.matches(item)]
        if offenders:
            return Status.FAIL, (
                f"filter {probe.name}={probe.value} not honored: "
                f"{len(offenders)} item(s) do not match"
            )
        if probe.expect_match and not filtered_items:
            return Status.FAIL, (
                f"filter {probe.name}={probe.value} omitted the known matching item"
            )
        if not probe.expect_match and (filtered_items or filtered["pagination"]["total"] != 0):
            return Status.FAIL, (
                f"filter {probe.name}={probe.value} reported unexpected matching items"
            )

    limited = _get_json(ctx, url, params={"limit": 1, "offset": 0})
    if limited is None:
        return Status.FAIL, "limit filter did not return 200 with a JSON object"
    limit_problems = _validate_discovery_body(limited, expected_limit=1, expected_offset=0)
    if limit_problems:
        return Status.FAIL, f"limit filter not honored: {limit_problems[0]}"
    base_total = body["pagination"]["total"]
    if limited["pagination"]["total"] != base_total:
        return Status.FAIL, "limit filter changed pagination.total"

    offset_page = _get_json(ctx, url, params={"limit": 100, "offset": 1})
    if offset_page is None:
        return Status.FAIL, "offset filter did not return 200 with a JSON object"
    offset_problems = _validate_discovery_body(offset_page, expected_limit=100, expected_offset=1)
    if offset_problems:
        return Status.FAIL, f"offset filter not honored: {offset_problems[0]}"
    if offset_page["pagination"]["total"] != base_total:
        return Status.FAIL, "offset filter changed pagination.total"
    offset_items: list[Any] = offset_page["items"]
    if len(items) >= 2 and (
        not offset_items
        or not isinstance(offset_items[0], dict)
        or offset_items[0].get("resource") != items[1].get("resource")
    ):
        return Status.FAIL, "offset=1 did not start at the second unfiltered item"
    if base_total == 1 and offset_items:
        return Status.FAIL, "offset=1 returned an item although pagination.total is 1"

    return Status.PASS, ("filters honored: type, payTo, scheme, network, extensions, limit, offset")


# Cap the number of listings considered in addition to the request-level caps in
# ``_SafeCrossFetcher`` so a large catalogue cannot turn one check into a crawl.
_MAX_STALENESS_ITEMS = 5


def _accept_identity(a: dict[str, Any]) -> tuple[str, str, str, str]:
    """Fields that decide where money goes and on which rail.

    ``amount`` is deliberately excluded: dynamic pricing is legitimate (RS-PR-012),
    so an amount delta alone must not read as a stale or misleading listing.
    """
    return (
        str(a.get("scheme")),
        str(a.get("network")),
        str(a.get("asset")).lower(),
        str(a.get("payTo")).lower(),
    )


@_register(
    "DI-003",
    "Listed accepts are consistent with the resource's live 402 (staleness)",
    Severity.MINOR,
    f"{_CORE} section 8.3 + arXiv:2605.11781 (IV metadata manipulation)",
)
def di_003(ctx: DiscoveryContext) -> tuple[Status, str]:
    body = _get_json(ctx, _resources_url(ctx.base_url))
    if body is None or not isinstance(body.get("items"), list) or not body["items"]:
        return Status.SKIP, "no discoverable items to cross-check"

    from ..probe import build_probe

    checked = 0
    blocked_or_unreachable = 0
    problems: list[str] = []
    for item in body["items"][:_MAX_STALENESS_ITEMS]:
        if not isinstance(item, dict):
            continue
        resource = item.get("resource")
        listed = item.get("accepts")
        if not (isinstance(resource, str) and isinstance(listed, list) and listed):
            continue
        try:
            probe = build_probe(ctx.cross_fetch(resource))
        except (CrossFetchError, httpx.HTTPError, OSError):
            blocked_or_unreachable += 1
            continue
        raw = probe.raw
        live = raw.get("accepts") if isinstance(raw, dict) else None
        if not isinstance(live, list) or not live:
            continue
        checked += 1
        live_ids = {_accept_identity(a) for a in live if isinstance(a, dict)}
        for accepted in listed:
            if isinstance(accepted, dict) and _accept_identity(accepted) not in live_ids:
                identity = _accept_identity(accepted)
                problems.append(
                    f"{_display_url(resource)}: listed {identity[0]}/{identity[1]} "
                    f"asset {identity[2]} payTo {identity[3]} not in live 402"
                )

    if checked == 0:
        suffix = (
            f" ({blocked_or_unreachable} blocked or unreachable)" if blocked_or_unreachable else ""
        )
        return Status.SKIP, "no listed resource returned a comparable live 402" + suffix
    if problems:
        return Status.FAIL, "; ".join(problems[:4])
    detail = f"{checked} listing(s) consistent with their live 402"
    if blocked_or_unreachable:
        detail += f"; {blocked_or_unreachable} blocked or unreachable"
    return Status.PASS, detail


def evaluate_discovery(ctx: DiscoveryContext | None) -> list[CheckResult]:
    results: list[CheckResult] = []
    for check in DI_REGISTRY:
        if ctx is None:
            status, detail = Status.SKIP, "discovery endpoint unreachable"
        else:
            try:
                status, detail = check.func(ctx)
            except httpx.HTTPError:
                raise
            except Exception as exc:
                status, detail = Status.ERROR, f"check crashed (suite bug): {exc!r}"
        results.append(
            CheckResult(check.check_id, check.title, check.severity, check.spec_ref, status, detail)
        )
    return results


def run_discovery_checks(
    base_url: str,
    timeout: float = 10.0,
    transport: httpx.BaseTransport | None = None,
    *,
    cross_fetch_allowlist: Sequence[str] = (),
    resolver: AddressResolver = _system_resolver,
) -> list[CheckResult]:
    """Run Discovery checks.

    ``cross_fetch_allowlist`` accepts exact hostnames, IP addresses, and CIDRs. It is
    intentionally empty by default. ``transport`` and ``resolver`` are test seams;
    normal network calls pin the validated DNS result to the actual TCP connection.
    """
    allowlist = _CrossFetchAllowlist.parse(cross_fetch_allowlist)
    headers = {"User-Agent": USER_AGENT}
    with httpx.Client(
        timeout=timeout, transport=transport, headers=headers, follow_redirects=False
    ) as client:
        fetcher = _SafeCrossFetcher(
            timeout=timeout,
            resolver=resolver,
            allowlist=allowlist,
            test_client=client if transport is not None else None,
        )
        return evaluate_discovery(
            DiscoveryContext(base_url=base_url, client=client, cross_fetch=fetcher)
        )
