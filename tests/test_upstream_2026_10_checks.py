"""Fixes and checks from the 2026-10 upstream review (f62a9fa..cb0ec5b).

See docs/upstream-review-2026-10.md. Each section names the review finding it
implements, so a failure here points at the upstream change it guards.
"""

from __future__ import annotations

import copy
from typing import Any

import httpx
import pytest
from conftest import TARGET_URL, encode_header

from x402_conformance.checks.base import Status
from x402_conformance.checks.discovery import run_discovery_checks
from x402_conformance.models import DiscoveryResponse
from x402_conformance.runner import run_checks

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


# ==========================================================================
# Shared: run the passive suite against a 402 with a given accepts array
# ==========================================================================

SOLANA = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
SOL_USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
SOL_PAYTO = "2wKupLR9q6wXYppw8Gr2NvWxKBUqm4PPJKkQfoxHDBg4"


def _accept(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "scheme": "exact",
        "network": "eip155:84532",
        "amount": "10000",
        "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
        "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
        "maxTimeoutSeconds": 60,
        "extra": {"name": "USDC", "version": "2"},
    }
    base.update(over)
    return base


def _sol(**over: Any) -> dict[str, Any]:
    return _accept(network=SOLANA, asset=SOL_USDC, payTo=SOL_PAYTO, **over)


def _run_accepts(payload: dict[str, Any], accepts: list[dict[str, Any]]) -> dict[str, Any]:
    out = copy.deepcopy(payload)
    out["accepts"] = accepts
    header = encode_header(out)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(402, headers={"PAYMENT-REQUIRED": header}, json={})

    results = run_checks(TARGET_URL, transport=httpx.MockTransport(handler))
    return {r.check_id: r for r in results}


# ==========================================================================
# §3 — RS-PR-019 vocabulary per (scheme, network family)
# ==========================================================================

#: The five spec-conformant shapes the old two-set model failed.
_CONFORMANT_SHAPES = {
    "exact SVM": _sol(extra={"feePayer": SOL_PAYTO, "recentBlockhash": "abc"}),
    "exact SVM upfront": _sol(
        extra={"feePayer": SOL_PAYTO, "paymentFlow": "upfront", "memo": "order-1"}
    ),
    "upto EVM": _accept(
        scheme="upto",
        extra={"name": "USDC", "version": "2", "facilitatorAddress": "0xabc"},
    ),
    "exact Hedera": _accept(
        network="hedera:testnet", asset="0.0.429274", payTo="0.0.1234", extra={"feePayer": "0.0.98"}
    ),
    "exact Starknet": _accept(network="starknet:SN_SEPOLIA", extra={"feePayer": "0x1"}),
    "batch-settlement SVM": _sol(
        scheme="batch-settlement",
        extra={"feePayer": SOL_PAYTO, "receiverAuthorizer": SOL_PAYTO, "withdrawDelay": 900},
    ),
    "auth-capture EVM": _accept(
        scheme="auth-capture",
        extra={
            "name": "USDC",
            "version": "2",
            "captureAuthorizer": "0x1",
            "operatorType": "delegated",
        },
    ),
}


@pytest.mark.parametrize("shape", sorted(_CONFORMANT_SHAPES))
def test_rs_pr_019_passes_conformant_bindings(valid_payload: dict[str, Any], shape: str) -> None:
    result = _run_accepts(valid_payload, [_CONFORMANT_SHAPES[shape]])["RS-PR-019"]
    assert result.status is Status.PASS, (shape, result.detail)


def test_rs_pr_019_still_catches_a_key_from_another_binding(valid_payload: dict[str, Any]) -> None:
    """SVM channel fields on an EVM exact entry are still a copy-paste error."""
    entry = _accept(extra={"name": "USDC", "version": "2", "recentBlockhash": "abc"})
    result = _run_accepts(valid_payload, [entry])["RS-PR-019"]
    assert result.status is Status.FAIL
    assert "exact on eip155" in result.detail and "recentBlockhash" in result.detail


def test_rs_pr_019_does_not_grade_unknown_keys_or_bindings(valid_payload: dict[str, Any]) -> None:
    # A key no binding defines is not attributable to a wrong scheme.
    unknown_key = _accept(extra={"name": "USDC", "version": "2", "x-vendor": 1})
    assert _run_accepts(valid_payload, [unknown_key])["RS-PR-019"].status is Status.PASS
    # A binding without a vocabulary here is skipped, not failed, even with keys
    # another binding uses.
    aptos = _accept(network="aptos:1", extra={"feePayer": "0x1", "name": "x"})
    assert _run_accepts(valid_payload, [aptos])["RS-PR-019"].status is Status.SKIP


def test_rs_pr_017_explain_text_names_all_four_schemes() -> None:
    from x402_conformance.report import _REMEDIATION

    for scheme in ("exact", "upto", "batch-settlement", "auth-capture"):
        assert scheme in _REMEDIATION["RS-PR-017"]


# ==========================================================================
# §4 — RS-PR-026 is scheme-aware
# ==========================================================================


def test_rs_pr_026_svm_batch_settlement_is_not_told_to_declare_escrow(
    valid_payload: dict[str, Any],
) -> None:
    """Its flow, when present, MUST be authorization; advising escrow was backwards."""
    entry = _sol(
        scheme="batch-settlement",
        extra={"feePayer": SOL_PAYTO, "receiverAuthorizer": SOL_PAYTO, "withdrawDelay": 900},
    )
    assert _run_accepts(valid_payload, [entry])["RS-PR-026"].status is Status.SKIP


def test_rs_pr_026_auth_capture_default_escrow_is_advised(valid_payload: dict[str, Any]) -> None:
    """auth-capture defaults to escrow, so an undeclared flow joins the CORE-vs-binding
    contradiction SVM upto is already in: advisory, not graded."""
    entry = _accept(scheme="auth-capture", extra={"name": "USDC", "version": "2"})
    result = _run_accepts(valid_payload, [entry])["RS-PR-026"]
    assert result.status is Status.PASS
    assert result.detail.startswith("advisory:")
    assert "defaults to escrow" in result.detail


def test_rs_pr_026_auto_capture_is_no_longer_an_escrow_signal(
    valid_payload: dict[str, Any],
) -> None:
    entry = _accept(extra={"name": "USDC", "version": "2", "autoCapture": False})
    assert _run_accepts(valid_payload, [entry])["RS-PR-026"].status is Status.SKIP


def test_rs_pr_026_unknown_binding_falls_back_to_signals(valid_payload: dict[str, Any]) -> None:
    entry = _accept(network="aptos:1", extra={"withdrawDelay": 60})
    result = _run_accepts(valid_payload, [entry])["RS-PR-026"]
    assert result.status is Status.PASS and "withdrawDelay" in result.detail


def test_rs_pr_026_evm_upto_is_authorization(valid_payload: dict[str, Any]) -> None:
    entry = _accept(scheme="upto", extra={"name": "USDC", "version": "2", "withdrawDelay": 60})
    assert _run_accepts(valid_payload, [entry])["RS-PR-026"].status is Status.SKIP


# ==========================================================================
# §7 — RS-PR-018 groups by the reserved keys too (x402#3145)
# ==========================================================================


def test_rs_pr_018_same_asset_per_flow_is_not_a_contradiction(
    valid_payload: dict[str, Any],
) -> None:
    upfront = _sol(amount="10000", extra={"feePayer": SOL_PAYTO, "paymentFlow": "upfront"})
    authorization = _sol(
        amount="12000", extra={"feePayer": SOL_PAYTO, "paymentFlow": "authorization"}
    )
    result = _run_accepts(valid_payload, [upfront, authorization])["RS-PR-018"]
    assert result.status is Status.PASS


def test_rs_pr_018_same_flow_twice_still_fails(valid_payload: dict[str, Any]) -> None:
    a = _sol(amount="10000", extra={"paymentFlow": "upfront"})
    b = _sol(amount="12000", extra={"paymentFlow": "upfront"})
    result = _run_accepts(valid_payload, [a, b])["RS-PR-018"]
    assert result.status is Status.FAIL
    assert "paymentFlow='upfront'" in result.detail
