"""Tests for the DI discovery checks against correct and buggy mock Bazaars."""

from __future__ import annotations

import json

import httpx

from x402_conformance.checks import Status
from x402_conformance.checks.discovery import run_discovery_checks

BASE = "http://bazaar.example"

ITEM = {
    "resource": "https://api.example.com/premium-data",
    "type": "http",
    "x402Version": 2,
    "accepts": [{"scheme": "exact", "network": "eip155:84532", "amount": "10000",
                 "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
                 "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C", "maxTimeoutSeconds": 60}],
    "lastUpdated": 1703123456,
}


def make_bazaar(*, body: dict | None = None, honor_filter: bool = True) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if not request.url.path.endswith("/discovery/resources"):
            return httpx.Response(404)
        if body is not None:
            return httpx.Response(200, json=body)
        network = request.url.params.get("network")
        items = [ITEM]
        if network and not honor_filter:
            # buggy: return an item that does NOT match the requested network
            other = json.loads(json.dumps(ITEM))
            other["accepts"][0]["network"] = "eip155:1"
            items = [other]
        try:
            limit = int(request.url.params.get("limit", 20))
        except ValueError:
            limit = 20
        return httpx.Response(200, json={
            "x402Version": 2, "items": items,
            "pagination": {"limit": limit, "offset": 0, "total": len(items)},
        })

    return httpx.MockTransport(handler)


def by_id(results, cid):
    return next(r for r in results if r.check_id == cid)


def test_correct_bazaar_passes() -> None:
    results = run_discovery_checks(BASE, transport=make_bazaar())
    assert by_id(results, "DI-001").status == Status.PASS
    assert by_id(results, "DI-002").status == Status.PASS


def test_missing_pagination_fails() -> None:
    bad = {"x402Version": 2, "items": [ITEM]}  # no pagination
    results = run_discovery_checks(BASE, transport=make_bazaar(body=bad))
    assert by_id(results, "DI-001").status == Status.FAIL


def test_item_missing_resource_fails() -> None:
    broken_item = {"type": "http", "accepts": []}  # no resource
    bad = {"x402Version": 2, "items": [broken_item],
           "pagination": {"limit": 20, "offset": 0, "total": 1}}
    results = run_discovery_checks(BASE, transport=make_bazaar(body=bad))
    r = by_id(results, "DI-001")
    assert r.status == Status.FAIL
    assert "resource" in r.detail


def test_unhonored_network_filter_caught() -> None:
    results = run_discovery_checks(BASE, transport=make_bazaar(honor_filter=False))
    assert by_id(results, "DI-002").status == Status.FAIL


def test_empty_catalogue_skips_filter_check() -> None:
    empty = {"x402Version": 2, "items": [], "pagination": {"limit": 20, "offset": 0, "total": 0}}
    results = run_discovery_checks(BASE, transport=make_bazaar(body=empty))
    assert by_id(results, "DI-001").status == Status.PASS  # empty is schema-valid
    assert by_id(results, "DI-002").status == Status.SKIP
