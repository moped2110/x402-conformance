"""Discovery checks against correct, buggy, and hostile mock Bazaars."""

from __future__ import annotations

import base64
import copy
import json
from collections.abc import Iterable
from typing import Any

import httpx
import pytest

from x402_conformance.checks import Status
from x402_conformance.checks.discovery import (
    CrossFetchError,
    _CrossFetchAllowlist,
    _SafeCrossFetcher,
    run_discovery_checks,
)

BASE = "http://bazaar.example"
PUBLIC_IP = "93.184.216.34"

ACCEPT = {
    "scheme": "exact",
    "network": "eip155:84532",
    "amount": "10000",
    "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
    "maxTimeoutSeconds": 60,
}
ITEM = {
    "resource": "https://api.example.com/premium-data",
    "type": "http",
    "x402Version": 2,
    "accepts": [ACCEPT],
    "lastUpdated": 1703123456,
    "extensions": {"bazaar": {"category": "finance"}},
}
OTHER_ITEM = {
    "resource": "https://other.example.com/tool",
    "type": "mcp",
    "x402Version": 1,
    "accepts": [
        {
            "scheme": "upto",
            "network": "eip155:43113",
            "amount": "20000",
            "asset": "0x0000000000000000000000000000000000000001",
            "payTo": "0x0000000000000000000000000000000000000002",
            "maxTimeoutSeconds": 30.5,
            "extra": {},
        }
    ],
    "lastUpdated": 1703123556.5,
    "extensions": {"other-extension": {}},
}


def public_resolver(_host: str, _port: int) -> Iterable[str]:
    return [PUBLIC_IP]


def _encode_header(payload: dict[str, Any]) -> str:
    return base64.b64encode(json.dumps(payload).encode()).decode()


def _live_402(resource: str, accepts: list[dict[str, Any]]) -> httpx.Response:
    payload = {
        "x402Version": 2,
        "error": "payment required",
        "resource": {"url": resource},
        "accepts": accepts,
        "extensions": {},
    }
    return httpx.Response(402, headers={"PAYMENT-REQUIRED": _encode_header(payload)})


def make_bazaar(
    *,
    body: dict[str, Any] | None = None,
    ignored_filter: str | None = None,
    live_accepts: dict[str, list[dict[str, Any]]] | None = None,
    redirect: dict[str, str] | None = None,
    seen: list[str] | None = None,
) -> httpx.MockTransport:
    """Return a spec-shaped Bazaar with independently breakable filters."""

    catalogue = [ITEM, OTHER_ITEM]

    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(str(request.url))
        if request.url.path.endswith("/discovery/resources"):
            if body is not None:
                return httpx.Response(200, json=body)
            items = copy.deepcopy(catalogue)
            predicates = {
                "type": lambda item, value: item["type"] == value,
                "payTo": lambda item, value: any(
                    accepted["payTo"] == value for accepted in item["accepts"]
                ),
                "scheme": lambda item, value: any(
                    accepted["scheme"] == value for accepted in item["accepts"]
                ),
                "network": lambda item, value: any(
                    accepted["network"] == value for accepted in item["accepts"]
                ),
                "extensions": lambda item, value: value in item.get("extensions", {}),
            }
            for name, predicate in predicates.items():
                value = request.url.params.get(name)
                if value is not None and ignored_filter != name:
                    items = [item for item in items if predicate(item, value)]
            total = len(items)
            requested_limit = int(request.url.params.get("limit", 20))
            requested_offset = int(request.url.params.get("offset", 0))
            limit = 20 if ignored_filter == "limit" else requested_limit
            offset = 0 if ignored_filter == "offset" else requested_offset
            items = items[offset : offset + limit]
            return httpx.Response(
                200,
                json={
                    "x402Version": 2,
                    "items": items,
                    "pagination": {"limit": limit, "offset": offset, "total": total},
                },
            )
        resource_url = str(request.url)
        if redirect is not None and resource_url in redirect:
            return httpx.Response(302, headers={"Location": redirect[resource_url]})
        if live_accepts is not None and resource_url in live_accepts:
            return _live_402(resource_url, live_accepts[resource_url])
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def run(
    transport: httpx.MockTransport,
    *,
    resolver=public_resolver,
    allowlist: tuple[str, ...] = (),
):
    return run_discovery_checks(
        BASE,
        transport=transport,
        resolver=resolver,
        cross_fetch_allowlist=allowlist,
    )


def by_id(results, cid):
    return next(result for result in results if result.check_id == cid)


def valid_body(*, items: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    selected = copy.deepcopy([ITEM] if items is None else items)
    return {
        "x402Version": 2,
        "items": selected,
        "pagination": {"limit": 20, "offset": 0, "total": len(selected)},
    }


def test_correct_bazaar_passes_schema_and_all_filters() -> None:
    results = run(make_bazaar())
    assert by_id(results, "DI-001").status == Status.PASS
    filter_result = by_id(results, "DI-002")
    assert filter_result.status == Status.PASS
    assert "extensions" in filter_result.detail
    assert "offset" in filter_result.detail


@pytest.mark.parametrize(
    ("description", "mutate", "expected_detail"),
    [
        ("top version", lambda body: body.update(x402Version="2"), "x402Version"),
        ("items", lambda body: body.update(items={}), "items"),
        ("pagination", lambda body: body.pop("pagination"), "pagination"),
        ("resource", lambda body: body["items"][0].pop("resource"), "resource"),
        ("type", lambda body: body["items"][0].update(type=False), "type"),
        ("item version", lambda body: body["items"][0].update(x402Version=True), "x402Version"),
        ("accepts", lambda body: body["items"][0].update(accepts=[]), "accepts"),
        ("lastUpdated", lambda body: body["items"][0].update(lastUpdated="now"), "lastUpdated"),
        (
            "requirement field",
            lambda body: body["items"][0]["accepts"][0].pop("payTo"),
            "payTo",
        ),
        (
            "requirement network",
            lambda body: body["items"][0]["accepts"][0].update(network="base-sepolia"),
            "CAIP-2",
        ),
        (
            "requirement timeout",
            lambda body: body["items"][0]["accepts"][0].update(maxTimeoutSeconds="60"),
            "maxTimeoutSeconds",
        ),
        (
            "extensions",
            lambda body: body["items"][0].update(extensions=[]),
            "extensions",
        ),
        ("limit", lambda body: body["pagination"].update(limit=101), "limit"),
        ("offset", lambda body: body["pagination"].update(offset=-1), "offset"),
        ("total", lambda body: body["pagination"].update(total=True), "total"),
    ],
)
def test_di_001_rejects_each_invalid_schema_field(description, mutate, expected_detail) -> None:
    del description
    body = valid_body()
    mutate(body)
    result = by_id(run(make_bazaar(body=body)), "DI-001")
    assert result.status == Status.FAIL
    assert expected_detail in result.detail


def test_di_001_accepts_empty_catalogue() -> None:
    body = valid_body(items=[])
    results = run(make_bazaar(body=body))
    assert by_id(results, "DI-001").status == Status.PASS
    assert by_id(results, "DI-002").status == Status.SKIP


@pytest.mark.parametrize(
    "ignored_filter",
    ["type", "payTo", "scheme", "network", "extensions", "limit", "offset"],
)
def test_di_002_catches_each_ignored_filter(ignored_filter: str) -> None:
    result = by_id(run(make_bazaar(ignored_filter=ignored_filter)), "DI-002")
    assert result.status == Status.FAIL
    assert ignored_filter in result.detail


def test_di_002_rejects_invalid_filtered_response() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        if request.url.path.endswith("/discovery/resources"):
            calls += 1
            body = valid_body(items=[ITEM, OTHER_ITEM])
            if calls > 2:
                body["pagination"]["limit"] = "100"
            return httpx.Response(200, json=body)
        return httpx.Response(404)

    result = by_id(run(httpx.MockTransport(handler)), "DI-002")
    assert result.status == Status.FAIL
    assert "invalid data" in result.detail


# --- DI-003: safe listing-to-live-402 cross-fetches --------------------------


def _single_resource_body(resource: str) -> dict[str, Any]:
    item = copy.deepcopy(ITEM)
    item["resource"] = resource
    return valid_body(items=[item])


def _transport_for_resource(
    resource: str,
    *,
    live: bool = False,
    redirect_to: str | None = None,
    seen: list[str] | None = None,
) -> httpx.MockTransport:
    body = _single_resource_body(resource)

    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(str(request.url))
        if request.url.path.endswith("/discovery/resources"):
            return httpx.Response(200, json=body)
        if str(request.url) == resource and redirect_to is not None:
            return httpx.Response(302, headers={"Location": redirect_to})
        if str(request.url) == resource and live:
            return _live_402(resource, copy.deepcopy(ITEM["accepts"]))
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def test_di_003_passes_when_public_listing_matches_live() -> None:
    resource = ITEM["resource"]
    result = by_id(run(_transport_for_resource(resource, live=True)), "DI-003")
    assert result.status == Status.PASS


def test_di_003_flags_a_manipulated_payto_without_query_leak() -> None:
    resource = "https://api.example.com/premium-data?api_key=secret"
    body = _single_resource_body(resource)
    tampered = copy.deepcopy(ITEM["accepts"])
    tampered[0]["payTo"] = "0x000000000000000000000000000000000000dEaD"
    transport = make_bazaar(
        body=body,
        live_accepts={resource: tampered},
    )
    result = by_id(run(transport), "DI-003")
    assert result.status == Status.FAIL
    assert "not in live 402" in result.detail
    assert "secret" not in result.detail


def test_di_003_skips_when_resource_unreachable() -> None:
    result = by_id(run(_transport_for_resource(ITEM["resource"])), "DI-003")
    assert result.status == Status.SKIP


@pytest.mark.parametrize(
    "resource",
    [
        "http://127.0.0.1/admin",
        "http://169.254.169.254/latest/meta-data",
        "http://10.0.0.1/internal",
        "http://0.0.0.0/",
        "http://224.0.0.1/",
        "http://192.0.2.1/",
        "http://[::1]/",
        "http://[fe80::1]/",
        "http://[fc00::1]/",
        "http://[::]/",
        "http://[ff02::1]/",
        "http://[2001:db8::1]/",
        "http://[::ffff:127.0.0.1]/",
    ],
)
def test_di_003_blocks_non_public_ipv4_and_ipv6_literals(resource: str) -> None:
    seen: list[str] = []
    result = by_id(run(_transport_for_resource(resource, live=True, seen=seen)), "DI-003")
    assert result.status == Status.SKIP
    assert all(str(httpx.URL(resource).host) not in url for url in seen)


@pytest.mark.parametrize("host", ["2130706433", "0x7f000001", "017700000001"])
def test_di_003_blocks_numeric_ipv4_aliases_after_dns_resolution(host: str) -> None:
    seen: list[str] = []

    def alias_resolver(_host: str, _port: int) -> Iterable[str]:
        return ["127.0.0.1"]

    resource = f"http://{host}/admin"
    result = by_id(
        run(_transport_for_resource(resource, live=True, seen=seen), resolver=alias_resolver),
        "DI-003",
    )
    assert result.status == Status.SKIP
    assert not any(host in url for url in seen)


def test_di_003_blocks_dns_name_if_any_answer_is_private() -> None:
    seen: list[str] = []

    def mixed_resolver(_host: str, _port: int) -> Iterable[str]:
        return [PUBLIC_IP, "10.0.0.8"]

    resource = "https://mixed.example/internal"
    result = by_id(
        run(_transport_for_resource(resource, live=True, seen=seen), resolver=mixed_resolver),
        "DI-003",
    )
    assert result.status == Status.SKIP
    assert not any("mixed.example" in url for url in seen)


def test_di_003_rejects_userinfo_before_request() -> None:
    seen: list[str] = []
    resource = "https://user:password@api.example.com/private"
    result = by_id(run(_transport_for_resource(resource, live=True, seen=seen)), "DI-003")
    assert result.status == Status.SKIP
    assert not any("password" in url for url in seen)


def test_di_003_revalidates_and_blocks_redirect_to_private_address() -> None:
    seen: list[str] = []
    resource = "https://public.example/start"
    metadata = "http://169.254.169.254/latest/meta-data"
    result = by_id(
        run(_transport_for_resource(resource, redirect_to=metadata, seen=seen)),
        "DI-003",
    )
    assert result.status == Status.SKIP
    assert any("public.example" in url for url in seen)
    assert not any("169.254.169.254" in url for url in seen)


def test_di_003_rejects_https_to_http_redirect_even_when_public() -> None:
    seen: list[str] = []
    resource = "https://public.example/start"
    downgrade = "http://other-public.example/live"
    result = by_id(
        run(_transport_for_resource(resource, redirect_to=downgrade, seen=seen)),
        "DI-003",
    )
    assert result.status == Status.SKIP
    assert not any("other-public.example" in url for url in seen)


def test_di_003_private_destination_requires_explicit_allowlist() -> None:
    resource = "http://169.254.169.254/test-fixture"
    result = by_id(
        run(
            _transport_for_resource(resource, live=True),
            allowlist=("169.254.169.254/32",),
        ),
        "DI-003",
    )
    assert result.status == Status.PASS


def test_cross_fetch_pins_validated_dns_answer_against_rebinding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolutions = 0
    connected: list[str] = []

    def rebinding_resolver(_host: str, _port: int) -> Iterable[str]:
        nonlocal resolutions
        resolutions += 1
        return [PUBLIC_IP] if resolutions == 1 else ["127.0.0.1"]

    fetcher = _SafeCrossFetcher(
        timeout=1,
        resolver=rebinding_resolver,
        allowlist=_CrossFetchAllowlist(),
    )

    def fake_pinned_request(target, address):
        connected.append(str(address))
        return httpx.Response(200, request=httpx.Request("GET", target.url))

    monkeypatch.setattr(fetcher, "_request_pinned", fake_pinned_request)
    response = fetcher("https://rebind.example/resource")
    assert response.status_code == 200
    assert resolutions == 1
    assert connected == [PUBLIC_IP]


def test_cross_fetch_enforces_redirect_and_request_caps() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(302, headers={"Location": f"/redirect-{calls}"})

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    try:
        fetcher = _SafeCrossFetcher(
            timeout=1,
            resolver=public_resolver,
            allowlist=_CrossFetchAllowlist(),
            test_client=client,
        )
        with pytest.raises(CrossFetchError, match="more than 3 redirects"):
            fetcher("https://public.example/start")
        assert calls == 4
    finally:
        client.close()


@pytest.mark.parametrize(
    "entry",
    ["", "*.internal.example", "https://internal.example", "10.0.0.0/not-a-prefix"],
)
def test_invalid_private_allowlist_is_rejected(entry: str) -> None:
    with pytest.raises(ValueError, match="allowlist"):
        run_discovery_checks(BASE, cross_fetch_allowlist=(entry,))
