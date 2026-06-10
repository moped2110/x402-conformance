"""Tests for RS-HS handshake checks and the runner plumbing."""

from __future__ import annotations

import httpx

from x402_conformance.checks import Severity, Status
from x402_conformance.report import exit_code
from x402_conformance.runner import run_checks

from conftest import TARGET_URL, transport_with_402


def by_id(results: list, check_id: str):
    return next(r for r in results if r.check_id == check_id)


def test_spec_example_endpoint_is_conformant(valid_transport: httpx.MockTransport) -> None:
    """The spec's own example payload must pass every gating check."""
    results = run_checks(TARGET_URL, transport=valid_transport)
    gating_failures = [
        r
        for r in results
        if r.status in (Status.FAIL, Status.ERROR)
        and r.severity in (Severity.CRITICAL, Severity.MAJOR)
    ]
    assert gating_failures == [], [f"{r.check_id}: {r.detail}" for r in gating_failures]
    assert exit_code(results) == 0


def test_non_402_response_fails_handshake() -> None:
    transport = transport_with_402(None, status_code=200)
    results = run_checks(TARGET_URL, transport=transport)
    assert by_id(results, "RS-HS-001").status == Status.FAIL
    assert "without payment" in by_id(results, "RS-HS-001").detail
    assert by_id(results, "RS-HS-002").status == Status.SKIP
    assert exit_code(results) == 1


def test_402_without_payment_required_header_fails() -> None:
    transport = transport_with_402(None, status_code=402)
    results = run_checks(TARGET_URL, transport=transport)
    assert by_id(results, "RS-HS-001").status == Status.PASS
    assert by_id(results, "RS-HS-002").status == Status.FAIL
    assert exit_code(results) == 1


def test_invalid_base64_header_fails() -> None:
    transport = transport_with_402(None, header_value="not%%%base64!!!")
    results = run_checks(TARGET_URL, transport=transport)
    assert by_id(results, "RS-HS-003").status == Status.FAIL
    assert by_id(results, "RS-HS-004").status == Status.SKIP


def test_valid_base64_invalid_json_fails() -> None:
    import base64

    transport = transport_with_402(None, header_value=base64.b64encode(b"{not json").decode())
    results = run_checks(TARGET_URL, transport=transport)
    assert by_id(results, "RS-HS-003").status == Status.PASS
    assert by_id(results, "RS-HS-004").status == Status.FAIL


def test_schema_violation_fails(valid_payload: dict) -> None:
    del valid_payload["accepts"]
    transport = transport_with_402(valid_payload)
    results = run_checks(TARGET_URL, transport=transport)
    r = by_id(results, "RS-HS-004")
    assert r.status == Status.FAIL
    assert "accepts" in r.detail


def test_legacy_headers_flagged(valid_payload: dict) -> None:
    transport = transport_with_402(valid_payload, extra_headers={"X-PAYMENT": "legacy"})
    results = run_checks(TARGET_URL, transport=transport)
    r = by_id(results, "RS-HS-005")
    assert r.status == Status.FAIL
    assert r.severity == Severity.MINOR
    # minor failure alone must NOT gate the verdict
    assert exit_code(results) == 0
