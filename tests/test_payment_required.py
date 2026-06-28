"""Tests for RS-PR PaymentRequired content checks."""

from __future__ import annotations

import pytest

from x402_conformance.checks import Status
from x402_conformance.report import exit_code
from x402_conformance.runner import run_checks

from conftest import TARGET_URL, transport_with_402
from test_handshake import by_id


def test_v1_endpoint_is_bucketed_not_failed() -> None:
    # A recognized x402 v1 envelope (real JPYC deployments still emit v1): version 1,
    # no v2 top-level `resource`, accepts without the v2-required maxTimeoutSeconds.
    # It must read as "speaks v1, not v2" (bucketed SKIPs under RS-PR-001), not a pile
    # of v2-shape failures that flip the verdict — and the version-agnostic rail checks
    # still run and pass.
    v1 = {
        "x402Version": 1,
        "accepts": [
            {
                "scheme": "exact",
                "network": "eip155:137",
                "amount": "1000000000000000000",
                "asset": "0xE7C3D8C9a439feDe00D2600032D5dB0Be71C3c29",
                "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
                "extra": {"name": "JPY Coin", "version": "1"},
            }
        ],
    }
    results = run_checks(TARGET_URL, transport=transport_with_402(v1))
    assert by_id(results, "RS-PR-001").status == Status.SKIP
    assert "v1" in by_id(results, "RS-PR-001").detail
    assert by_id(results, "RS-PR-002").status == Status.SKIP
    assert by_id(results, "RS-PR-005").status == Status.SKIP
    assert by_id(results, "RS-HS-004").status == Status.SKIP
    # version-agnostic rail checks still run on the v1 envelope
    assert by_id(results, "RS-PR-006").status == Status.PASS  # CAIP-2 network
    assert by_id(results, "RS-PR-009").status == Status.PASS  # extra.name/version
    # a clean v1 endpoint must not gate the verdict
    assert exit_code(results) == 0


def test_unknown_version_still_fails(valid_payload: dict) -> None:
    # An unrecognized/garbage version is a real malformation — still a FAIL.
    valid_payload["x402Version"] = 3
    results = run_checks(TARGET_URL, transport=transport_with_402(valid_payload))
    assert by_id(results, "RS-PR-001").status == Status.FAIL


def test_resource_url_mismatch(valid_payload: dict) -> None:
    valid_payload["resource"]["url"] = "https://api.example.com/other-endpoint"
    results = run_checks(TARGET_URL, transport=transport_with_402(valid_payload))
    assert by_id(results, "RS-PR-003").status == Status.FAIL


def test_resource_url_trailing_slash_tolerated(valid_payload: dict) -> None:
    valid_payload["resource"]["url"] = TARGET_URL + "/"
    results = run_checks(TARGET_URL, transport=transport_with_402(valid_payload))
    assert by_id(results, "RS-PR-003").status == Status.PASS


def test_pr_008_valid_eip55_checksum_passes(valid_payload: dict) -> None:
    # The fixture asset is the canonical (checksummed) Base Sepolia USDC address.
    results = run_checks(TARGET_URL, transport=transport_with_402(valid_payload))
    assert by_id(results, "RS-PR-008").status == Status.PASS


def test_pr_008_bad_eip55_checksum_caught(valid_payload: dict) -> None:
    pytest.importorskip("eth_utils")
    asset = valid_payload["accepts"][0]["asset"]
    # Flip the case of the final hex nibble → mixed-case but invalid checksum.
    valid_payload["accepts"][0]["asset"] = asset[:-1] + asset[-1].swapcase()
    results = run_checks(TARGET_URL, transport=transport_with_402(valid_payload))
    assert by_id(results, "RS-PR-008").status == Status.FAIL


def test_pr_008_lowercase_address_is_format_only_pass(valid_payload: dict) -> None:
    # All-lowercase = unchecksummed, a legitimate form → no checksum to fail.
    valid_payload["accepts"][0]["asset"] = valid_payload["accepts"][0]["asset"].lower()
    results = run_checks(TARGET_URL, transport=transport_with_402(valid_payload))
    assert by_id(results, "RS-PR-008").status == Status.PASS


def test_empty_accepts(valid_payload: dict) -> None:
    valid_payload["accepts"] = []
    results = run_checks(TARGET_URL, transport=transport_with_402(valid_payload))
    assert by_id(results, "RS-PR-004").status == Status.FAIL


def test_missing_required_accept_field(valid_payload: dict) -> None:
    del valid_payload["accepts"][0]["payTo"]
    results = run_checks(TARGET_URL, transport=transport_with_402(valid_payload))
    r = by_id(results, "RS-PR-005")
    assert r.status in (Status.FAIL, Status.SKIP)  # schema parse already fails -> raw check still runs
    # the raw-level check must name the missing field
    if r.status == Status.FAIL:
        assert "payTo" in r.detail


def test_non_caip2_network(valid_payload: dict) -> None:
    valid_payload["accepts"][0]["network"] = "base-sepolia"  # V1 style, not CAIP-2
    results = run_checks(TARGET_URL, transport=transport_with_402(valid_payload))
    assert by_id(results, "RS-PR-006").status == Status.FAIL


def test_amount_as_number_fails(valid_payload: dict) -> None:
    valid_payload["accepts"][0]["amount"] = 10000  # must be string
    results = run_checks(TARGET_URL, transport=transport_with_402(valid_payload))
    assert by_id(results, "RS-PR-007").status == Status.FAIL


def test_amount_with_decimals_fails(valid_payload: dict) -> None:
    valid_payload["accepts"][0]["amount"] = "0.01"  # not atomic units
    results = run_checks(TARGET_URL, transport=transport_with_402(valid_payload))
    assert by_id(results, "RS-PR-007").status == Status.FAIL


def test_malformed_evm_asset(valid_payload: dict) -> None:
    valid_payload["accepts"][0]["asset"] = "0x1234"
    results = run_checks(TARGET_URL, transport=transport_with_402(valid_payload))
    assert by_id(results, "RS-PR-008").status == Status.FAIL


def test_missing_eip712_domain(valid_payload: dict) -> None:
    valid_payload["accepts"][0]["extra"] = {}
    results = run_checks(TARGET_URL, transport=transport_with_402(valid_payload))
    r = by_id(results, "RS-PR-009")
    assert r.status == Status.FAIL
    assert "name" in r.detail and "version" in r.detail


def test_too_many_tags(valid_payload: dict) -> None:
    valid_payload["resource"]["tags"] = [f"tag-{i}" for i in range(6)]
    results = run_checks(TARGET_URL, transport=transport_with_402(valid_payload))
    assert by_id(results, "RS-PR-010").status == Status.FAIL


def test_extension_missing_schema(valid_payload: dict) -> None:
    valid_payload["extensions"] = {"my-ext": {"info": {"a": 1}}}
    results = run_checks(TARGET_URL, transport=transport_with_402(valid_payload))
    r = by_id(results, "RS-PR-011")
    assert r.status == Status.FAIL
    assert "schema" in r.detail


def test_stable_requirements_pass(valid_payload: dict) -> None:
    results = run_checks(TARGET_URL, transport=transport_with_402(valid_payload))
    assert by_id(results, "RS-PR-012").status == Status.PASS


def test_jp402_absent_skips(valid_payload: dict) -> None:
    # Opt-in JP-rail check: no x-jp402 advertised → SKIP (never gates a non-JP endpoint).
    results = run_checks(TARGET_URL, transport=transport_with_402(valid_payload))
    assert by_id(results, "RS-PR-015").status == Status.SKIP


def test_jp402_valid_invoice_passes(valid_payload: dict) -> None:
    valid_payload["accepts"][0]["x-jp402"] = {"invoice": {"registrationNumber": "T1234567890123"}}
    results = run_checks(TARGET_URL, transport=transport_with_402(valid_payload))
    assert by_id(results, "RS-PR-015").status == Status.PASS


def test_jp402_bad_t_number_fails_but_does_not_gate(valid_payload: dict) -> None:
    valid_payload["accepts"][0]["x-jp402"] = {"invoice": {"registrationNumber": "T12345"}}
    results = run_checks(TARGET_URL, transport=transport_with_402(valid_payload))
    r = by_id(results, "RS-PR-015")
    assert r.status == Status.FAIL
    assert "registrationNumber" in r.detail
    assert exit_code(results) == 0  # MINOR — must not flip the verdict
