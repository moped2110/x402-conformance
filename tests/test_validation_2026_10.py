"""Regressions from the 2026-10-07 real-target validation against x402@cb0ec5b.

* RS-NEG-012 failed the conformant Go example server, which rejects an unknown
  x402Version with 400 (the Python one answers 402); both are clean rejections.
* RS-NEG-001/002 rightly fail the Python example (402 for a malformed header where
  transports-v2/http.md says 400), and now say that the cause is the upstream SDK.
* FA-VER-003 passed x402.org with a non-canonical invalidReason that only the
  detail text mentioned; it is now tagged and named in the summary.
"""

from __future__ import annotations

import base64
import json

import httpx
import pytest

pytest.importorskip("eth_account")

from test_negative import SIGNER, TARGET, by_id, make_server

from x402_conformance.active import run_active_checks
from x402_conformance.checks import Status
from x402_conformance.checks.base import NONCANONICAL_REASON
from x402_conformance.checks.facilitator import _EOA_ASSET, FacilitatorContext, evaluate_facilitator
from x402_conformance.payload_builder import EvmSigner
from x402_conformance.report import to_json, to_markdown


def _with(inner: httpx.MockTransport, override):  # type: ignore[no-untyped-def]
    """Wrap a mock server: ``override(request)`` may answer first, else ``inner`` does."""

    def handler(request: httpx.Request) -> httpx.Response:
        answer = override(request)
        return answer if answer is not None else inner.handle_request(request)

    return httpx.MockTransport(handler)


def _decoded(request: httpx.Request) -> dict | None:  # type: ignore[type-arg]
    sig = request.headers.get("PAYMENT-SIGNATURE")
    if sig is None:
        return None
    try:
        doc = json.loads(base64.b64decode(sig, validate=True))
    except ValueError:
        return None
    return doc if isinstance(doc, dict) else None


@pytest.mark.parametrize("status", [400, 402])
def test_neg_012_accepts_400_or_402_for_an_unknown_version(status: int) -> None:
    def override(request: httpx.Request) -> httpx.Response | None:
        doc = _decoded(request)
        if doc is not None and doc.get("x402Version") == 99:
            return httpx.Response(status)
        return None

    results = run_active_checks(TARGET, SIGNER, transport=_with(make_server(), override))
    r = by_id(results, "RS-NEG-012")
    assert r.status is Status.PASS, r.detail
    assert f"status {status}" in r.detail


def test_neg_012_still_fails_on_other_statuses() -> None:
    def override(request: httpx.Request) -> httpx.Response | None:
        doc = _decoded(request)
        return httpx.Response(404) if doc is not None and doc.get("x402Version") == 99 else None

    results = run_active_checks(TARGET, SIGNER, transport=_with(make_server(), override))
    assert by_id(results, "RS-NEG-012").status is Status.FAIL


def test_malformed_header_answered_with_402_fails_with_the_python_sdk_note() -> None:
    def override(request: httpx.Request) -> httpx.Response | None:
        sig = request.headers.get("PAYMENT-SIGNATURE")
        if sig is not None and _decoded(request) is None:
            return httpx.Response(402)  # the Python SDK's behaviour at x402@cb0ec5b
        return None

    results = run_active_checks(TARGET, SIGNER, transport=_with(make_server(), override))
    for cid in ("RS-NEG-001", "RS-NEG-002"):
        r = by_id(results, cid)
        assert r.status is Status.FAIL
        assert "Python SDK" in r.detail and "expected 400" in r.detail


def test_malformed_header_answered_with_400_passes_without_a_note() -> None:
    results = run_active_checks(TARGET, SIGNER, transport=make_server())
    for cid in ("RS-NEG-001", "RS-NEG-002"):
        r = by_id(results, cid)
        assert r.status is Status.PASS and "Python SDK" not in r.detail


_REQ = {
    "scheme": "exact",
    "network": "eip155:84532",
    "amount": "10000",
    "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
    "maxTimeoutSeconds": 300,
    "extra": {"name": "USDC", "version": "2"},
}


def _fac(reason: str) -> FacilitatorContext:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/verify"):
            body = json.loads(request.content)
            if body["paymentRequirements"]["asset"].lower() == _EOA_ASSET.lower():
                return httpx.Response(200, json={"isValid": False, "invalidReason": reason})
            return httpx.Response(200, json={"isValid": True})
        return httpx.Response(404)

    return FacilitatorContext(
        base_url="http://fac.test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        requirements=_REQ,
        signer=EvmSigner.from_key("0x" + "33" * 32),
    )


def test_fa_ver_003_tags_a_noncanonical_reason_and_names_it_in_the_summary() -> None:
    results = evaluate_facilitator(_fac("invalid_exact_evm_eip3009_not_supported"))
    r = by_id(results, "FA-VER-003")
    assert r.status is Status.PASS
    assert r.reason_code == NONCANONICAL_REASON
    assert "invalid_exact_evm_eip3009_not_supported" in r.detail
    md = to_markdown(results, "http://fac.test")
    assert "**Passed with a non-canonical reason:** FA-VER-003" in md
    doc = json.loads(to_json(results, "http://fac.test"))
    assert doc["exitCode"] in (0, 1, 2)
    tagged = [x for x in doc["results"] if x["check_id"] == "FA-VER-003"]
    assert tagged[0]["reason_code"] == NONCANONICAL_REASON


def test_fa_ver_003_canonical_reason_is_untagged() -> None:
    r = by_id(evaluate_facilitator(_fac("asset_not_deployed_contract")), "FA-VER-003")
    assert r.status is Status.PASS and r.reason_code is None


def test_noncanonical_reason_does_not_change_the_verdict() -> None:
    from x402_conformance.report import assessment_exit_code

    base = evaluate_facilitator(_fac("asset_not_deployed_contract"))
    noted = evaluate_facilitator(_fac("invalid_exact_evm_eip3009_not_supported"))
    assert assessment_exit_code(base) == assessment_exit_code(noted)


def test_console_shows_the_note_and_full_target(capsys: pytest.CaptureFixture[str]) -> None:
    from x402_conformance.cli import _emit

    results = evaluate_facilitator(_fac("invalid_exact_evm_eip3009_not_supported"))
    _emit(results, "https://x402.org/facilitator", False, None, None)
    out = capsys.readouterr().out
    assert "Passed with a non-canonical reason: FA-VER-003" in out
    assert "(https://x402.org/facilitator)" in out
    assert "non-canonical reason 'invalid_exact_evm_eip3009_not_supported'" in out
