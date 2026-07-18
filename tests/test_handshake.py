"""Tests for RS-HS handshake checks and the runner plumbing."""

from __future__ import annotations

import httpx
import pytest
from conftest import (
    TARGET_URL,
    VALID_PAYMENT_REQUIRED,
    encode_header,
    transport_with_402,
)

from x402_conformance import runner
from x402_conformance.checks import Severity, Status
from x402_conformance.report import exit_code
from x402_conformance.runner import EndpointUnreachable, run_checks


def by_id(results: list, check_id: str):
    return next(r for r in results if r.check_id == check_id)


def test_selected_method_is_never_changed_implicitly() -> None:
    # Passive checks must describe the selected request, not probe another verb.
    methods: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        methods.append(request.method)
        if request.method == "GET":
            return httpx.Response(405, json={})
        return httpx.Response(
            402,
            headers={"PAYMENT-REQUIRED": encode_header(VALID_PAYMENT_REQUIRED)},
            json={},
        )

    results = run_checks(TARGET_URL, transport=httpx.MockTransport(handler))
    assert by_id(results, "RS-HS-001").status == Status.FAIL
    assert set(methods) == {"GET"}


def test_no_method_switch_when_neither_verb_is_a_paywall() -> None:
    # Both verbs 405 → no paywall to find → keep the original response, report it faithfully.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(405, json={})

    results = run_checks(TARGET_URL, transport=httpx.MockTransport(handler))
    assert by_id(results, "RS-HS-001").status == Status.FAIL


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


# --- K1-3: `check` aimed at a facilitator endpoint is inconclusive, not FAIL ---

_FACILITATOR_URL = "https://facilitator.example.com/supported"


def test_facilitator_endpoint_skips_instead_of_failing_the_handshake() -> None:
    # A facilitator's /supported correctly answers 200, not 402. Pointing the passive
    # resource `check` at it is the wrong subcommand, not a broken paywall — so
    # RS-HS-001 must not manufacture a FAIL out of a legitimately-200 endpoint.
    transport = transport_with_402(None, status_code=200)
    results = run_checks(_FACILITATOR_URL, transport=transport)
    hs001 = by_id(results, "RS-HS-001")
    assert hs001.status == Status.SKIP
    assert "facilitator" in hs001.detail
    # The skip carries the machine reason, so the run's verdict can name endpoint_absent.
    assert hs001.reason_code == "endpoint_absent"


def test_a_facilitator_check_is_inconclusive_never_conformant() -> None:
    # The false-PASS guard: with RS-HS-001 skipped the run must not read as a green
    # verdict. Everything skips, so the assessment is inconclusive (exit 2), never 0.
    from x402_conformance.report import assessment_exit_code

    transport = transport_with_402(None, status_code=200)
    results = run_checks(_FACILITATOR_URL, transport=transport)
    assert not any(r.status == Status.FAIL for r in results)
    assert assessment_exit_code(results) == 2


def test_a_facilitator_path_that_still_signals_x402_is_not_excused() -> None:
    # The guard is tight: the skip only applies when there is no paywall signal. A
    # 200 that nonetheless carries a PAYMENT-REQUIRED header is malformed and must
    # still gate — a facilitator path is not a blanket exemption.
    transport = transport_with_402(VALID_PAYMENT_REQUIRED, status_code=200)
    results = run_checks(_FACILITATOR_URL, transport=transport)
    assert by_id(results, "RS-HS-001").status == Status.FAIL


def test_a_normal_resource_serving_200_still_fails() -> None:
    # The revenue-leak case must be untouched: a plain customer URL that serves
    # content without a 402 is a real failure, facilitator handling notwithstanding.
    transport = transport_with_402(None, status_code=200)
    results = run_checks("https://api.example.com/premium-data", transport=transport)
    assert by_id(results, "RS-HS-001").status == Status.FAIL


# --- T-23: infra 5xx is unreachable, not a conformance FAIL ------------------


def test_server_error_no_paywall_is_unreachable() -> None:
    # A Cloudflare 530 (origin down) is an infra failure, not a verdict — the run
    # bails to unreachable instead of emitting a MAJOR RS-HS-001 FAIL.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(530)

    with pytest.raises(EndpointUnreachable):
        run_checks(TARGET_URL, transport=httpx.MockTransport(handler))


def test_transient_503_is_retried_then_paywall(monkeypatch) -> None:
    monkeypatch.setattr(runner.time, "sleep", lambda _s: None)  # no real backoff
    header = encode_header(VALID_PAYMENT_REQUIRED)
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(503)  # one transient blip
        return httpx.Response(402, headers={"PAYMENT-REQUIRED": header}, json={})

    results = run_checks(TARGET_URL, transport=httpx.MockTransport(handler))
    assert by_id(results, "RS-HS-001").status == Status.PASS
    assert calls["n"] >= 2  # the 503 was retried, not reported


def test_persistent_503_is_unreachable_after_retries(monkeypatch) -> None:
    monkeypatch.setattr(runner.time, "sleep", lambda _s: None)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    with pytest.raises(EndpointUnreachable):
        run_checks(TARGET_URL, transport=httpx.MockTransport(handler))


def test_5xx_with_paywall_signal_skips_not_fails() -> None:
    # A 5xx that still carries a PAYMENT-REQUIRED header isn't unreachable — the
    # checks run, and RS-HS-001 treats the 5xx as inconclusive (SKIP), never FAIL.
    header = encode_header(VALID_PAYMENT_REQUIRED)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, headers={"PAYMENT-REQUIRED": header}, json={})

    results = run_checks(TARGET_URL, transport=httpx.MockTransport(handler))
    assert by_id(results, "RS-HS-001").status == Status.SKIP
    # The SKIP is inconclusive, not a gating failure — a valid paywall header with a
    # 5xx body doesn't flip the run to non-conformant on its own.
    assert exit_code(results) == 0


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


def test_v1_envelope_skips_v2_schema_check() -> None:
    # An x402 v1 envelope fails the v2 schema, but it's a version mismatch, not a
    # malformation — RS-HS-004 skips it (bucketed under RS-PR-001), not FAIL.
    v1 = {
        "x402Version": 1,
        "accepts": [
            {
                "scheme": "exact",
                "network": "eip155:137",
                "amount": "1",
                "asset": "0x" + "ab" * 20,
                "payTo": "0x" + "cd" * 20,
                "extra": {"name": "JPY Coin", "version": "1"},
            }
        ],
    }
    results = run_checks(TARGET_URL, transport=transport_with_402(v1))
    assert by_id(results, "RS-HS-004").status == Status.SKIP


def test_legacy_headers_flagged(valid_payload: dict) -> None:
    transport = transport_with_402(valid_payload, extra_headers={"X-PAYMENT": "legacy"})
    results = run_checks(TARGET_URL, transport=transport)
    r = by_id(results, "RS-HS-005")
    assert r.status == Status.FAIL
    assert r.severity == Severity.MINOR
    # minor failure alone must NOT gate the verdict
    assert exit_code(results) == 0
