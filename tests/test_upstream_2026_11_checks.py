"""Checks from the 2026-11 upstream review (cb0ec5b..e7cdc70).

See docs/upstream-review-2026-11.md. Each section names the decision it
implements, so a failure here points at the upstream change it guards.
"""

from __future__ import annotations

import base64
import copy
import json
from typing import Any

import httpx
import pytest
from conftest import TARGET_URL, VALID_PAYMENT_REQUIRED, encode_header
from eth_account import Account
from test_negative import SIGNER, TARGET, make_server

from x402_conformance.active import run_active_checks
from x402_conformance.checks.base import Status
from x402_conformance.payload_builder import build_exact_eip3009_payload, tamper_high_s
from x402_conformance.runner import CORS_PROBE_ORIGIN, run_checks


def _passive(challenge: dict[str, Any], **hooks: Any) -> dict[str, Any]:
    """Run the passive group against a server answering with ``challenge``."""

    def handler(request: httpx.Request) -> httpx.Response:
        hook = hooks.get("handler")
        if hook is not None:
            answered = hook(request)
            if answered is not None:
                return answered
        return httpx.Response(402, headers={"PAYMENT-REQUIRED": encode_header(challenge)})

    results = run_checks(TARGET_URL, transport=httpx.MockTransport(handler))
    return {r.check_id: r for r in results}


# ==========================================================================
# Decision 5 — `extra.splits` is tolerated by RS-PR-019 (x402#3221)
# ==========================================================================


@pytest.mark.parametrize("network", ["eip155:84532", "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"])
def test_rs_pr_019_tolerates_splits_on_every_exact_binding(network: str) -> None:
    challenge = copy.deepcopy(VALID_PAYMENT_REQUIRED)
    entry = challenge["accepts"][0]
    entry["network"] = network
    if network.startswith("solana:"):
        entry["extra"] = {"feePayer": entry["payTo"]}
    entry.setdefault("extra", {})["splits"] = [{"payTo": entry["payTo"], "amount": "1"}]
    r = _passive(challenge)["RS-PR-019"]
    assert r.status is Status.PASS, r.detail


def test_rs_pr_019_still_flags_splits_outside_exact() -> None:
    challenge = copy.deepcopy(VALID_PAYMENT_REQUIRED)
    entry = challenge["accepts"][0]
    entry["scheme"] = "upto"
    entry["extra"] = {"name": "USDC", "version": "2", "splits": []}
    r = _passive(challenge)["RS-PR-019"]
    assert r.status is Status.FAIL and "splits" in r.detail


# ==========================================================================
# Decision 8 — builder-code `m` in a 402 is advisory (x402#3666)
# ==========================================================================


def test_rs_pr_023_advises_on_facilitator_metadata_in_a_402() -> None:
    challenge = copy.deepcopy(VALID_PAYMENT_REQUIRED)
    challenge["extensions"] = {"builder-code": {"info": {"a": "bc_app", "m": {"x402X": 1}}}}
    r = _passive(challenge)["RS-PR-023"]
    assert r.status is Status.PASS
    assert r.detail.startswith("advisory:") and "`m`" in r.detail


def test_rs_pr_023_keeps_failing_a_bad_app_code_next_to_m() -> None:
    challenge = copy.deepcopy(VALID_PAYMENT_REQUIRED)
    challenge["extensions"] = {"builder-code": {"info": {"a": "Bad-Code", "m": {}}}}
    r = _passive(challenge)["RS-PR-023"]
    assert r.status is Status.FAIL and "advisory:" in r.detail


def test_rs_pr_023_without_m_is_unchanged() -> None:
    challenge = copy.deepcopy(VALID_PAYMENT_REQUIRED)
    challenge["extensions"] = {"builder-code": {"info": {"a": "bc_app"}}}
    r = _passive(challenge)["RS-PR-023"]
    assert (r.status, r.detail) == (Status.PASS, "")


# ==========================================================================
# Decision 6 — RS-HS-010 browser/CORS guidance, advisory (x402#3809)
# ==========================================================================


def _cors_handler(
    *,
    expose: str | None = "PAYMENT-REQUIRED, PAYMENT-RESPONSE",
    allow_headers: str = "content-type, payment-signature",
    paywall_preflight: bool = False,
    acao: bool = True,
) -> Any:
    challenge = VALID_PAYMENT_REQUIRED

    def hook(request: httpx.Request) -> httpx.Response | None:
        origin = request.headers.get("origin")
        if request.method == "OPTIONS":
            if paywall_preflight:
                return httpx.Response(402, headers={"PAYMENT-REQUIRED": encode_header(challenge)})
            headers = {"Access-Control-Allow-Headers": allow_headers}
            if acao and origin:
                headers["Access-Control-Allow-Origin"] = origin
            return httpx.Response(204, headers=headers)
        if origin is None:
            return None
        headers = {"PAYMENT-REQUIRED": encode_header(challenge)}
        if acao:
            headers["Access-Control-Allow-Origin"] = origin
        if expose is not None:
            headers["Access-Control-Expose-Headers"] = expose
        return httpx.Response(402, headers=headers)

    return hook


def test_rs_hs_010_browser_ready_server_passes_clean() -> None:
    r = _passive(VALID_PAYMENT_REQUIRED, handler=_cors_handler())["RS-HS-010"]
    assert (r.status, r.detail) == (Status.PASS, "")


def test_rs_hs_010_probes_with_a_reserved_origin() -> None:
    seen: list[tuple[str, str | None]] = []

    def hook(request: httpx.Request) -> None:
        seen.append((request.method, request.headers.get("origin")))

    _passive(VALID_PAYMENT_REQUIRED, handler=hook)
    assert ("OPTIONS", CORS_PROBE_ORIGIN) in seen
    assert ("GET", CORS_PROBE_ORIGIN) in seen


def test_rs_hs_010_no_acao_is_advisory_not_a_fail() -> None:
    r = _passive(VALID_PAYMENT_REQUIRED, handler=_cors_handler(acao=False))["RS-HS-010"]
    assert r.status is Status.PASS
    assert r.detail.startswith("advisory:") and "Access-Control-Allow-Origin" in r.detail


def test_rs_hs_010_missing_expose_headers_is_advised() -> None:
    r = _passive(VALID_PAYMENT_REQUIRED, handler=_cors_handler(expose="PAYMENT-REQUIRED"))[
        "RS-HS-010"
    ]
    assert r.status is Status.PASS
    assert "PAYMENT-RESPONSE" in r.detail and "PAYMENT-REQUIRED and" not in r.detail


def test_rs_hs_010_wildcard_expose_is_named() -> None:
    r = _passive(VALID_PAYMENT_REQUIRED, handler=_cors_handler(expose="*"))["RS-HS-010"]
    assert r.status is Status.PASS and "credentialed" in r.detail


def test_rs_hs_010_paywalled_preflight_is_advised() -> None:
    r = _passive(VALID_PAYMENT_REQUIRED, handler=_cors_handler(paywall_preflight=True))["RS-HS-010"]
    assert r.status is Status.PASS and "preflight is paywalled" in r.detail


def test_rs_hs_010_preflight_without_payment_signature_is_advised() -> None:
    r = _passive(VALID_PAYMENT_REQUIRED, handler=_cors_handler(allow_headers="content-type"))[
        "RS-HS-010"
    ]
    assert r.status is Status.PASS and "PAYMENT-SIGNATURE" in r.detail


def test_rs_hs_010_skips_without_a_paywall() -> None:
    results = run_checks(
        TARGET_URL, transport=httpx.MockTransport(lambda request: httpx.Response(200))
    )
    r = next(r for r in results if r.check_id == "RS-HS-010")
    assert r.status is Status.SKIP


# ==========================================================================
# Decision 7 — new negatives: non-object JSON header (x402#4051), high-s (#3912)
# ==========================================================================


def _active(transport: httpx.BaseTransport) -> dict[str, Any]:
    return {r.check_id: r for r in run_active_checks(TARGET, SIGNER, transport=transport)}


def test_rs_neg_017_and_018_pass_against_a_correct_server() -> None:
    results = _active(make_server())
    assert results["RS-NEG-017"].status is Status.PASS, results["RS-NEG-017"].detail
    assert results["RS-NEG-018"].status is Status.PASS, results["RS-NEG-018"].detail
    assert "invalid_exact_evm_non_canonical_signature" in results["RS-NEG-018"].detail


def test_rs_neg_017_fails_a_server_that_crashes_on_a_json_array() -> None:
    inner = make_server()

    def handler(request: httpx.Request) -> httpx.Response:
        sig = request.headers.get("PAYMENT-SIGNATURE")
        if sig is not None:
            try:
                decoded = json.loads(base64.b64decode(sig))
            except Exception:
                decoded = {}
            if not isinstance(decoded, dict):
                return httpx.Response(500)  # attribute access on a list
        return inner.handle_request(request)

    r = _active(httpx.MockTransport(handler))["RS-NEG-017"]
    assert r.status is Status.FAIL and r.detail.startswith("JSON []")


def test_rs_neg_018_fails_a_server_without_the_low_s_rule() -> None:
    r = _active(make_server(check_low_s=False))["RS-NEG-018"]
    assert r.status is Status.FAIL and "SERVED" in r.detail


def test_high_s_twin_recovers_to_the_same_signer() -> None:
    req = VALID_PAYMENT_REQUIRED["accepts"][0]
    payload = build_exact_eip3009_payload(req, SIGNER, resource_url=TARGET)
    twin = tamper_high_s(payload)
    original = payload["payload"]["signature"]
    assert twin["payload"]["signature"] != original
    assert twin["payload"]["authorization"] == payload["payload"]["authorization"]
    sig = bytes.fromhex(twin["payload"]["signature"][2:])
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    assert int.from_bytes(sig[32:64], "big") > n // 2
    # applying it twice restores the canonical signature
    assert tamper_high_s(twin)["payload"]["signature"] == original
    assert Account  # eth_account is required for the active group
