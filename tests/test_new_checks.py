"""Tests for checks added from the uploaded testcase catalog (RS-HS-007, RS-PR-013/014)."""

from __future__ import annotations

from conftest import TARGET_URL, transport_with_402
from test_handshake import by_id

from x402_conformance.checks import Status
from x402_conformance.runner import run_checks

# --- RS-HS-007: cacheability of the 402 ---


def test_cacheable_402_fails(valid_payload: dict) -> None:
    transport = transport_with_402(
        valid_payload, extra_headers={"Cache-Control": "public, max-age=3600"}
    )
    results = run_checks(TARGET_URL, transport=transport)
    r = by_id(results, "RS-HS-007")
    assert r.status == Status.FAIL
    assert "cacheable" in r.detail


def test_no_store_402_passes(valid_payload: dict) -> None:
    transport = transport_with_402(valid_payload, extra_headers={"Cache-Control": "no-store"})
    results = run_checks(TARGET_URL, transport=transport)
    assert by_id(results, "RS-HS-007").status == Status.PASS


def test_missing_cache_control_passes_with_advice(valid_payload: dict) -> None:
    results = run_checks(TARGET_URL, transport=transport_with_402(valid_payload))
    r = by_id(results, "RS-HS-007")
    assert r.status == Status.PASS
    assert "no-store" in r.detail  # advisory note present


# --- RS-PR-013: payTo/asset namespace consistency ---


def test_solana_address_on_evm_network_fails(valid_payload: dict) -> None:
    # Solana-style (non-0x) payTo advertised on an eip155 network
    valid_payload["accepts"][0]["payTo"] = "CKPKJWNdJEqa81x7CkZ14BVPiY6y16Sxs7owznqtWYp5"
    results = run_checks(TARGET_URL, transport=transport_with_402(valid_payload))
    r = by_id(results, "RS-PR-013")
    assert r.status == Status.FAIL
    assert "EVM address" in r.detail


def test_consistent_evm_namespace_passes(valid_payload: dict) -> None:
    results = run_checks(TARGET_URL, transport=transport_with_402(valid_payload))
    assert by_id(results, "RS-PR-013").status == Status.PASS


# --- RS-PR-014: amount strictly positive ---


def test_zero_amount_fails(valid_payload: dict) -> None:
    valid_payload["accepts"][0]["amount"] = "0"
    results = run_checks(TARGET_URL, transport=transport_with_402(valid_payload))
    assert by_id(results, "RS-PR-014").status == Status.FAIL


def test_negative_amount_fails(valid_payload: dict) -> None:
    valid_payload["accepts"][0]["amount"] = "-100"
    results = run_checks(TARGET_URL, transport=transport_with_402(valid_payload))
    assert by_id(results, "RS-PR-014").status == Status.FAIL


def test_positive_amount_passes(valid_payload: dict) -> None:
    results = run_checks(TARGET_URL, transport=transport_with_402(valid_payload))
    assert by_id(results, "RS-PR-014").status == Status.PASS
