"""EXTENSION-RESPONSES (CORE §7.2.1, x402#3278/#3306/#3301).

A facilitator MAY return an ``EXTENSION-RESPONSES`` header on ``/verify`` and
``/settle``: base64 JSON keyed by extension name, for the resource server only.
bazaar.md: "server internal only; never forwarded to the buyer".

* RS-HS-009 (pay group, MAJOR): the buyer never sees it, on the 402 or the
  answer to the paid request.
* FA-EXT-001 (facilitator, MINOR): when sent on /verify, it is well-formed.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import httpx
import pytest

pytest.importorskip("eth_account")

from conftest import VALID_PAYMENT_REQUIRED, encode_header

from x402_conformance import safety
from x402_conformance.active import run_payment_checks
from x402_conformance.checks import Status
from x402_conformance.checks import payment as payment_mod
from x402_conformance.checks.facilitator import (
    extension_responses_problems,
    run_facilitator_checks,
)
from x402_conformance.models import VerifyResponse
from x402_conformance.payload_builder import EvmSigner

SIGNER = EvmSigner.from_key("0x" + "66" * 32)
RES = "http://resource.example/data"
FAC = "http://facilitator.example"
REQ = VALID_PAYMENT_REQUIRED["accepts"][0]


def _b64(obj: Any) -> str:
    return base64.b64encode(json.dumps(obj).encode()).decode()


BAZAAR_OK = _b64({"bazaar": {"status": "processing"}})


@pytest.fixture(autouse=True)
def _offline(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(safety, "read_rpc_chain_id", lambda _url: 84532)
    monkeypatch.setattr(payment_mod, "_read_token_balance", lambda *a: 10**9)
    monkeypatch.setattr(
        "x402_conformance.checks.payment._verify_tx_onchain",
        lambda *_a, **_k: (Status.PASS, "matching Transfer event"),
    )


# --- RS-HS-009 -----------------------------------------------------------------


def _resource_server(*, on_402: bool = False, on_paid: bool = False) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        sig = request.headers.get("PAYMENT-SIGNATURE")
        if sig is None:
            headers = {"PAYMENT-REQUIRED": encode_header(VALID_PAYMENT_REQUIRED)}
            if on_402:
                headers["EXTENSION-RESPONSES"] = BAZAAR_OK
            return httpx.Response(402, headers=headers)
        payer = json.loads(base64.b64decode(sig))["payload"]["authorization"]["from"]
        ok = {
            "success": True,
            "transaction": "0x" + "cd" * 32,
            "network": REQ["network"],
            "payer": payer,
        }
        headers = {"PAYMENT-RESPONSE": _b64(ok), "Cache-Control": "private"}
        if on_paid:
            headers["EXTENSION-RESPONSES"] = BAZAAR_OK
        return httpx.Response(200, headers=headers, content=b'{"data":"premium"}')

    return httpx.MockTransport(handler)


def _hs_009(transport: httpx.MockTransport) -> Any:
    results = run_payment_checks(RES, SIGNER, rpc_url="http://rpc.local", transport=transport)
    return next(r for r in results if r.check_id == "RS-HS-009")


def test_rs_hs_009_passes_when_the_buyer_never_sees_it() -> None:
    result = _hs_009(_resource_server())
    assert result.status is Status.PASS
    assert result.severity.value == "major"


@pytest.mark.parametrize(
    ("kw", "where"),
    [({"on_paid": True}, "paid response"), ({"on_402": True}, "unpaid 402")],
)
def test_rs_hs_009_fails_when_forwarded(kw: dict[str, bool], where: str) -> None:
    result = _hs_009(_resource_server(**kw))
    assert result.status is Status.FAIL
    assert where in result.detail


def test_rs_hs_009_is_in_the_pay_group_skip_set() -> None:
    from x402_conformance.checks.payment import PAY_CHECK_IDS, evaluate_payment

    assert "RS-HS-009" in PAY_CHECK_IDS
    skipped = {r.check_id: r for r in evaluate_payment(None)}
    assert skipped["RS-HS-009"].status is Status.SKIP


# --- FA-EXT-001 ----------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        _b64({"bazaar": {"status": "success"}}),
        _b64({"bazaar": {"status": "rejected", "rejectedReason": "schema invalid"}}),
        _b64({"bazaar": {"status": "processing"}, "vendor-x": {}}),
        _b64({}),
    ],
)
def test_well_formed_extension_responses(value: str) -> None:
    assert extension_responses_problems(value) == []


@pytest.mark.parametrize(
    ("value", "needle"),
    [
        ("not base64!!", "not base64"),
        (_b64(["bazaar"]), "not an object"),
        (_b64({"bazaar": "processing"}), "not an object"),
        (_b64({"bazaar": {"status": "queued"}}), "bazaar.status"),
        (_b64({"bazaar": {"status": "rejected", "rejectedReason": 7}}), "rejectedReason"),
    ],
)
def test_malformed_extension_responses(value: str, needle: str) -> None:
    problems = extension_responses_problems(value)
    assert problems and needle in "; ".join(problems)


def test_verify_response_lets_extensions_through() -> None:
    """VerifyResponse gained optional `extensions` upstream; the strict model must
    keep accepting it (it does via extra="allow" — this keeps that true)."""
    parsed = VerifyResponse.model_validate(
        {
            "isValid": True,
            "payer": "0x" + "11" * 20,
            "extensions": {"bazaar": {"status": "success"}},
        }
    )
    assert parsed.is_valid


def _facilitator(header: str | None) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/data":
            return httpx.Response(
                402, headers={"PAYMENT-REQUIRED": encode_header(VALID_PAYMENT_REQUIRED)}
            )
        if request.url.path == "/supported":
            return httpx.Response(404)
        headers = {"EXTENSION-RESPONSES": header} if header is not None else {}
        return httpx.Response(
            200,
            headers=headers,
            json={
                "isValid": False,
                "invalidReason": "invalid_exact_evm_payload_authorization_value_mismatch",
            },
        )

    return httpx.MockTransport(handler)


def _fa_ext(header: str | None) -> Any:
    results = run_facilitator_checks(
        FAC, resource_url=RES, signer=SIGNER, transport=_facilitator(header)
    )
    return next(r for r in results if r.check_id == "FA-EXT-001")


def test_fa_ext_001_skips_when_absent() -> None:
    assert _fa_ext(None).status is Status.SKIP


def test_fa_ext_001_passes_a_well_formed_header() -> None:
    result = _fa_ext(BAZAAR_OK)
    assert result.status is Status.PASS
    assert result.severity.value == "minor"


def test_fa_ext_001_fails_a_malformed_header() -> None:
    result = _fa_ext(_b64({"bazaar": {"status": "queued"}}))
    assert result.status is Status.FAIL
    assert "bazaar.status" in result.detail
