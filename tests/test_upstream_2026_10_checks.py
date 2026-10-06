"""Fixes and checks from the 2026-10 upstream review (f62a9fa..cb0ec5b).

See docs/upstream-review-2026-10.md. Each section names the review finding it
implements, so a failure here points at the upstream change it guards.
"""

from __future__ import annotations

import copy
from typing import Any

import httpx
import pytest

from x402_conformance.checks.base import Status
from x402_conformance.checks.discovery import run_discovery_checks
from x402_conformance.models import DiscoveryResponse

# ==========================================================================
# §1 — Bazaar `lastUpdated` is an ISO 8601 string (x402#3067)
# ==========================================================================

_BAZAAR = "http://bazaar.example"

#: Shaped like a current CDP `/discovery/resources` page: V2 envelope, ISO
#: `lastUpdated`, no `metadata`, and the bazaar extension on the item.
_CDP_LIKE_ITEM: dict[str, Any] = {
    "resource": "https://api.example.com/weather",
    "type": "http",
    "x402Version": 2,
    "accepts": [
        {
            "scheme": "exact",
            "network": "eip155:8453",
            "amount": "10000",
            "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
            "maxTimeoutSeconds": 60,
            "extra": {"name": "USD Coin", "version": "2"},
        }
    ],
    "lastUpdated": "2026-09-30T14:03:11.482Z",
    "extensions": {"bazaar": {"info": {"input": {"type": "http", "method": "GET"}}}},
}


def _discovery(items: list[dict[str, Any]]) -> dict[str, Any]:
    def handler(request: httpx.Request) -> httpx.Response:
        if not request.url.path.endswith("/discovery/resources"):
            return httpx.Response(404)
        return httpx.Response(
            200,
            json={
                "x402Version": 2,
                "items": copy.deepcopy(items),
                "pagination": {
                    "limit": int(request.url.params.get("limit", 20)),
                    "offset": int(request.url.params.get("offset", 0)),
                    "total": len(items),
                },
            },
        )

    results = run_discovery_checks(_BAZAAR, transport=httpx.MockTransport(handler))
    return {r.check_id: r for r in results}


def _item(last_updated: object) -> dict[str, Any]:
    item = copy.deepcopy(_CDP_LIKE_ITEM)
    item["lastUpdated"] = last_updated
    return item


def test_current_bazaar_shape_passes_di_001_without_advisory() -> None:
    """The finding: every current Bazaar failed DI-001, a MAJOR check."""
    result = _discovery([_CDP_LIKE_ITEM])["DI-001"]
    assert result.status is Status.PASS
    assert "advisory" not in result.detail


@pytest.mark.parametrize(
    "stamp",
    [
        "2025-08-09T01:07:04.005Z",  # the CORE §8.1 example
        "2026-01-01T00:00:00Z",  # the Python SDK's fixtures
        "2025-08-09T01:07:04+02:00",
        "2025-08-09T01:07:04.123456789Z",  # Go's RFC3339Nano
    ],
)
def test_iso_8601_forms_are_accepted(stamp: str) -> None:
    assert _discovery([_item(stamp)])["DI-001"].status is Status.PASS


def test_numeric_last_updated_is_an_advisory_not_a_failure() -> None:
    """The V1 shape. Older facilitators still send it; it carries no payment
    semantics, so it is reported and never fails the MAJOR check."""
    result = _discovery([_item(1703123456)])["DI-001"]
    assert result.status is Status.PASS
    assert "advisory" in result.detail
    assert "items[0].lastUpdated" in result.detail
    assert "x402#3067" in result.detail


@pytest.mark.parametrize("bad", ["now", "2025-13-01T00:00:00Z", "2025-08-09", "", -1, True, None])
def test_a_value_that_is_neither_shape_still_fails(bad: object) -> None:
    result = _discovery([_item(bad)])["DI-001"]
    assert result.status is Status.FAIL
    assert "ISO 8601" in result.detail


# DI-002 re-validates every filtered page with the same helper. Its coverage is
# test_discovery.py::test_correct_bazaar_passes_schema_and_all_filters, whose
# catalogue now mixes an ISO item with a numeric one and must still PASS.


def test_discovery_model_accepts_iso_and_numeric_but_not_free_text() -> None:
    doc = {
        "x402Version": 2,
        "items": [_CDP_LIKE_ITEM],
        "pagination": {"limit": 20, "offset": 0, "total": 1},
    }
    assert DiscoveryResponse.model_validate(doc).items[0].last_updated == (
        "2026-09-30T14:03:11.482Z"
    )
    doc["items"] = [_item(1703123456)]
    assert DiscoveryResponse.model_validate(doc).items[0].last_updated == 1703123456
    doc["items"] = [_item("yesterday")]
    with pytest.raises(ValueError):
        DiscoveryResponse.model_validate(doc)
