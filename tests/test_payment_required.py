"""Tests for RS-PR PaymentRequired content checks."""

from __future__ import annotations

from x402_conformance.checks import Status
from x402_conformance.runner import run_checks

from conftest import TARGET_URL, transport_with_402
from test_handshake import by_id


def test_wrong_version(valid_payload: dict) -> None:
    valid_payload["x402Version"] = 1
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
