"""DI: discovery / Bazaar checks (catalog §7).

The Discovery API lets clients find x402 resources: ``GET /discovery/resources``
returns ``{x402Version, items[], pagination}`` where each item is a discovered
resource (``resource``, ``type``, ``accepts[]``, ``lastUpdated``). See CORE §8.

All checks here are passive GETs — no payment, no chain. Driven explicitly by
``run_discovery_checks``; not part of the passive REGISTRY.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx

from .base import CheckResult, Severity, Status

_CORE = "x402-specification-v2.md"
_CAIP2 = re.compile(r"^[a-z0-9-]{3,8}:[-_a-zA-Z0-9]{1,32}$")


@dataclass
class DiscoveryContext:
    base_url: str
    client: httpx.Client


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
        DI_REGISTRY.append(_DiCheck(cid, title, sev, ref, f))
        return f

    return deco


def _resources_url(base: str) -> str:
    return f"{base.rstrip('/')}/discovery/resources"


def _get_json(ctx: DiscoveryContext, url: str, params: dict[str, Any] | None = None) -> dict[str, Any] | None:
    try:
        resp = ctx.client.get(url, params=params)
        if resp.status_code != 200:
            return None
        import json

        data: Any = json.loads(resp.text)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


@_register("DI-001", "/discovery/resources returns schema-valid items + pagination",
           Severity.MAJOR, f"{_CORE} §8.1")
def di_001(ctx: DiscoveryContext) -> tuple[Status, str]:
    body = _get_json(ctx, _resources_url(ctx.base_url))
    if body is None:
        return Status.FAIL, "GET /discovery/resources did not return 200 with a JSON object"
    items = body.get("items")
    if not isinstance(items, list):
        return Status.FAIL, "`items` missing or not an array"
    pagination = body.get("pagination")
    if not isinstance(pagination, dict):
        return Status.FAIL, "`pagination` missing or not an object"
    for key in ("limit", "offset"):
        if not isinstance(pagination.get(key), int):
            return Status.FAIL, f"pagination.{key} missing or not an integer"
    problems = []
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            problems.append(f"items[{i}] not an object")
            continue
        if not isinstance(item.get("resource"), str) or not item["resource"]:
            problems.append(f"items[{i}].resource missing")
        if not isinstance(item.get("accepts"), list):
            problems.append(f"items[{i}].accepts missing or not an array")
    if problems:
        return Status.FAIL, "; ".join(problems[:6])
    return Status.PASS, f"{len(items)} item(s), schema-valid"


@_register("DI-002", "Discovery filters are honored (network)", Severity.MINOR, f"{_CORE} §8.1")
def di_002(ctx: DiscoveryContext) -> tuple[Status, str]:
    # Probe once unfiltered to find a network present in the catalogue.
    body = _get_json(ctx, _resources_url(ctx.base_url))
    if body is None or not isinstance(body.get("items"), list) or not body["items"]:
        return Status.SKIP, "no discoverable items to filter"
    networks: set[str] = set()
    for item in body["items"]:
        accepts = item.get("accepts") if isinstance(item, dict) else None
        if not isinstance(accepts, list):
            continue
        for a in accepts:
            net = a.get("network") if isinstance(a, dict) else None
            if isinstance(net, str) and _CAIP2.match(net):
                networks.add(net)
    if not networks:
        return Status.SKIP, "no CAIP-2 network found to filter by"
    network = sorted(networks)[0]
    filtered = _get_json(ctx, _resources_url(ctx.base_url), params={"network": network, "limit": 5})
    if filtered is None or not isinstance(filtered.get("items"), list):
        return Status.FAIL, f"filtered query (network={network}) did not return valid items"
    offenders = [
        item.get("resource")
        for item in filtered["items"]
        if not (isinstance(item.get("accepts"), list)
                and any(isinstance(a, dict) and a.get("network") == network for a in item["accepts"]))
    ]
    if offenders:
        return Status.FAIL, (
            f"filter network={network} not honored: {len(offenders)} item(s) lack that network"
        )
    pag = filtered.get("pagination")
    if isinstance(pag, dict) and isinstance(pag.get("limit"), int) and pag["limit"] > 5:
        return Status.FAIL, f"requested limit=5 but pagination.limit={pag['limit']}"
    return Status.PASS, f"network filter honored ({network})"


# Cap the live cross-fetch so a large catalogue doesn't turn one check into a crawl.
_MAX_STALENESS_ITEMS = 5


def _accept_identity(a: dict[str, Any]) -> tuple[str, str, str, str]:
    """The fields that decide WHERE money goes and on what rail — scheme, network,
    asset, payTo. `amount` is deliberately excluded: dynamic pricing is legitimate
    (RS-PR-012), so an amount delta must not read as a stale/misleading listing."""
    return (
        str(a.get("scheme")),
        str(a.get("network")),
        str(a.get("asset")).lower(),
        str(a.get("payTo")).lower(),
    )


@_register("DI-003", "Listed accepts are consistent with the resource's live 402 (staleness)",
           Severity.MINOR, f"{_CORE} §8.3 + arXiv:2605.11781 (IV metadata manipulation)")
def di_003(ctx: DiscoveryContext) -> tuple[Status, str]:
    # Cross-fetch each listed resource's live 402 and compare the advertised `accepts`
    # against reality. A listing whose (scheme/network/asset/payTo) isn't honored by the
    # resource's own 402 is stale — or a Bazaar metadata-manipulation lure that biases an
    # agent toward a payTo/asset the resource never asked for. Passive GETs only.
    body = _get_json(ctx, _resources_url(ctx.base_url))
    if body is None or not isinstance(body.get("items"), list) or not body["items"]:
        return Status.SKIP, "no discoverable items to cross-check"

    from ..probe import build_probe

    checked = 0
    problems: list[str] = []
    for item in body["items"][:_MAX_STALENESS_ITEMS]:
        if not isinstance(item, dict):
            continue
        resource = item.get("resource")
        listed = item.get("accepts")
        if not (isinstance(resource, str) and resource.startswith(("http://", "https://"))
                and isinstance(listed, list) and listed):
            continue
        try:
            probe = build_probe(ctx.client.get(resource))
        except Exception:
            continue  # resource unreachable — can't verify this listing, skip it
        raw = probe.raw
        live = raw.get("accepts") if isinstance(raw, dict) else None
        if not isinstance(live, list) or not live:
            continue  # no live 402 accepts to compare (not a 402 now / malformed)
        checked += 1
        live_ids = {_accept_identity(a) for a in live if isinstance(a, dict)}
        for a in listed:
            if isinstance(a, dict) and _accept_identity(a) not in live_ids:
                sid = _accept_identity(a)
                problems.append(f"{resource}: listed {sid[0]}/{sid[1]} asset {sid[2]} payTo {sid[3]} not in live 402")

    if checked == 0:
        return Status.SKIP, "no listed resource returned a comparable live 402"
    if problems:
        return Status.FAIL, "; ".join(problems[:4])
    return Status.PASS, f"{checked} listing(s) consistent with their live 402"


def evaluate_discovery(ctx: DiscoveryContext | None) -> list[CheckResult]:
    results: list[CheckResult] = []
    for check in DI_REGISTRY:
        if ctx is None:
            status, detail = Status.SKIP, "discovery endpoint unreachable"
        else:
            try:
                status, detail = check.func(ctx)
            except Exception as exc:
                status, detail = Status.ERROR, f"check crashed (suite bug): {exc!r}"
        results.append(CheckResult(check.check_id, check.title, check.severity,
                                   check.spec_ref, status, detail))
    return results


def run_discovery_checks(
    base_url: str,
    timeout: float = 10.0,
    transport: httpx.BaseTransport | None = None,
) -> list[CheckResult]:
    headers = {"User-Agent": "x402-conformance/0.1.0 (discovery)"}
    with httpx.Client(timeout=timeout, transport=transport, headers=headers,
                      follow_redirects=True) as client:
        return evaluate_discovery(DiscoveryContext(base_url=base_url, client=client))
