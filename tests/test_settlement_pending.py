"""`settlement_pending` (CORE §5.3.2/§9, x402#3083 and x402#3214).

A facilitator MAY answer `success: false, errorReason: "settlement_pending"` with
the broadcast hash when it sent a transaction but could not confirm it. The outcome
is non-terminal. The resource server retries `/settle` once with the identical
payload, and the facilitator reconciles against the stored hash instead of
broadcasting again.

Before the 2026-10 review the settlement model rejected any failed response with
a hash, so this whole flow graded as "invalid response". These tests pin the
replacement: pending is reported as inconclusive, the retry is graded as
reconciliation or double broadcast, and FA-SET-004 grades the hash itself.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Iterator

import httpx
import pytest

pytest.importorskip("eth_account")

from conftest import VALID_PAYMENT_REQUIRED, encode_header

from x402_conformance import safety
from x402_conformance.active import run_payment_checks
from x402_conformance.checks import Status
from x402_conformance.checks import payment as payment_mod
from x402_conformance.checks.base import SETTLEMENT_PENDING
from x402_conformance.checks.facilitator import run_facilitator_checks
from x402_conformance.payload_builder import EvmSigner
from x402_conformance.report import assessment_exit_code, assessment_reason

FAC = "http://facilitator.example"
RES = "http://resource.example/data"
REQ = VALID_PAYMENT_REQUIRED["accepts"][0]
SIGNER = EvmSigner.from_key("0x" + "55" * 32)
H1 = "0x" + "a1" * 32
H2 = "0x" + "b2" * 32


@pytest.fixture(autouse=True)
def _offline(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(safety, "read_rpc_chain_id", lambda _url: 84532)
    monkeypatch.setattr(payment_mod, "_read_token_balance", lambda *a: 10**9)
    monkeypatch.setattr(
        "x402_conformance.checks.payment._verify_tx_onchain",
        lambda *_a, **_k: (Status.PASS, "matching Transfer event"),
    )


def _pending(tx: str = H1) -> dict:
    return {
        "success": False,
        "errorReason": "settlement_pending",
        "transaction": tx,
        "network": REQ["network"],
    }


def _ok(tx: str = H1) -> dict:
    return {"success": True, "transaction": tx, "network": REQ["network"]}


def _failed(reason: str = "duplicate_settlement", tx: str = "") -> dict:
    return {"success": False, "errorReason": reason, "transaction": tx, "network": REQ["network"]}


def facilitator(
    valid_answers: list[dict], invalid_answer: dict | None = None
) -> httpx.MockTransport:
    """A facilitator whose /settle answers for the *valid* payment are scripted in
    order; the last one repeats. The underpaying payment gets ``invalid_answer``."""
    script: Iterator[dict] = iter(valid_answers)
    last: list[dict] = [valid_answers[-1]]

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "GET" and path == "/data":
            return httpx.Response(
                402, headers={"PAYMENT-REQUIRED": encode_header(VALID_PAYMENT_REQUIRED)}
            )
        if path == "/supported":
            return httpx.Response(404)
        body = json.loads(request.content)
        auth = body["paymentPayload"]["payload"]["authorization"]
        valid = int(auth["value"]) == int(body["paymentRequirements"]["amount"])
        if path == "/verify":
            if valid:
                return httpx.Response(200, json={"isValid": True, "payer": auth["from"]})
            return httpx.Response(
                200,
                json={
                    "isValid": False,
                    "invalidReason": "invalid_exact_evm_payload_authorization_value_mismatch",
                },
            )
        if not valid:
            return httpx.Response(200, json=invalid_answer or _failed("invalid_payload"))
        answer = next(script, last[0])
        return httpx.Response(200, json=answer)

    return httpx.MockTransport(handler)


def _settle(transport: httpx.MockTransport) -> dict:
    results = run_facilitator_checks(
        FAC,
        resource_url=RES,
        signer=SIGNER,
        allow_settle=True,
        rpc_url="http://rpc.local",
        transport=transport,
    )
    return {r.check_id: r for r in results if r.check_id.startswith("FA-SET")}


# --- facilitator /settle -------------------------------------------------------


def test_pending_then_confirmed_on_retry_is_graded_on_the_confirmed_answer() -> None:
    """The protocol's happy path: pending, one retry, same hash confirmed."""
    by_id = _settle(facilitator([_pending(H1), _ok(H1), _failed()]))
    assert by_id["FA-SET-001"].status is Status.PASS
    assert by_id["FA-SET-003"].status is Status.PASS
    assert by_id["FA-SET-002"].status is Status.PASS
    assert by_id["FA-SET-004"].status is Status.PASS


def test_still_pending_after_the_retry_is_inconclusive_not_failed() -> None:
    by_id = _settle(facilitator([_pending(H1), _pending(H1)]))
    first, double = by_id["FA-SET-001"], by_id["FA-SET-003"]
    assert first.status is Status.SKIP and first.reason_code == SETTLEMENT_PENDING
    assert double.status is Status.SKIP and double.reason_code == SETTLEMENT_PENDING
    assert H1 in first.detail
    results = list(by_id.values())
    assert assessment_exit_code(results) == 2
    assert assessment_reason(results) == SETTLEMENT_PENDING


def test_retry_with_a_different_hash_is_a_second_broadcast() -> None:
    """Reconciliation looks up the stored broadcast; a new hash means the same
    authorization went to the chain twice."""
    for retry in (_ok(H2), _pending(H2)):
        by_id = _settle(facilitator([_pending(H1), retry]))
        assert by_id["FA-SET-003"].status is Status.FAIL
        assert "re-broadcast" in by_id["FA-SET-003"].detail


def test_reconciled_repeat_with_the_same_hash_is_idempotent() -> None:
    """After a pending first answer, a later /settle reporting the same broadcast
    as settled moved nothing twice."""
    by_id = _settle(facilitator([_pending(H1), _ok(H1), _ok(H1)]))
    assert by_id["FA-SET-003"].status is Status.PASS
    assert "reconciled" in by_id["FA-SET-003"].detail


def test_a_second_success_after_a_terminal_success_still_fails() -> None:
    """The idempotency allowance is for reconciliation only, not a blanket pass."""
    by_id = _settle(facilitator([_ok(H1), _ok(H1)]))
    assert by_id["FA-SET-003"].status is Status.FAIL


def test_pending_that_resolves_to_a_failure_fails_the_valid_settle() -> None:
    by_id = _settle(facilitator([_pending(H1), _failed("invalid_transaction_state", H1)]))
    assert by_id["FA-SET-001"].status is Status.FAIL
    assert "after settlement_pending" in by_id["FA-SET-001"].detail


def test_pending_without_a_hash_fails_fa_set_004() -> None:
    by_id = _settle(facilitator([_pending(""), _pending("")]))
    assert by_id["FA-SET-004"].status is Status.FAIL
    assert by_id["FA-SET-004"].severity.value == "minor"
    assert by_id["FA-SET-001"].reason_code == SETTLEMENT_PENDING


def test_no_pending_answer_skips_fa_set_004() -> None:
    by_id = _settle(facilitator([_ok(H1), _failed()]))
    assert by_id["FA-SET-004"].status is Status.SKIP


def test_broadcasting_the_underpayment_fails_fa_set_002_even_when_pending() -> None:
    """A pending or reverted broadcast is legal in general, which is why the model
    now admits it. For FA-SET-002's payload it is not: the underpaying
    authorization should never have been broadcast."""
    by_id = _settle(facilitator([_ok(H1), _failed()], invalid_answer=_pending(H2)))
    assert by_id["FA-SET-002"].status is Status.FAIL
    assert "underpaying" in by_id["FA-SET-002"].detail


# --- resource server (RS-PAY) --------------------------------------------------


def _enc(obj: dict) -> str:
    return base64.b64encode(json.dumps(obj).encode()).decode()


def pending_server(settlement: dict) -> httpx.MockTransport:
    """A resource server that surfaces a pending settlement as a 402."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("PAYMENT-SIGNATURE") is None:
            return httpx.Response(
                402, headers={"PAYMENT-REQUIRED": encode_header(VALID_PAYMENT_REQUIRED)}
            )
        return httpx.Response(402, headers={"PAYMENT-RESPONSE": _enc(settlement)})

    return httpx.MockTransport(handler)


def test_pending_on_the_resource_server_is_inconclusive() -> None:
    results = run_payment_checks(
        RES, SIGNER, rpc_url="http://rpc.local", transport=pending_server(_pending(H1))
    )
    by_id = {r.check_id: r for r in results}
    assert by_id["RS-PAY-001"].status is Status.SKIP
    assert by_id["RS-PAY-001"].reason_code == SETTLEMENT_PENDING
    assert "reconcile" in by_id["RS-PAY-001"].detail
    # RS-PAY-002 used to FAIL here because the model rejected the header outright.
    assert by_id["RS-PAY-002"].status is Status.SKIP
    assert by_id["RS-PAY-002"].reason_code == SETTLEMENT_PENDING
    assert assessment_exit_code(results) == 2
    assert assessment_reason(results) == SETTLEMENT_PENDING


def test_pending_without_a_hash_on_the_resource_server_fails_rs_pay_002() -> None:
    results = run_payment_checks(
        RES, SIGNER, rpc_url="http://rpc.local", transport=pending_server(_pending(""))
    )
    by_id = {r.check_id: r for r in results}
    assert by_id["RS-PAY-002"].status is Status.FAIL
    assert "empty transaction" in by_id["RS-PAY-002"].detail


# --- RS-NEG keeps the semantic rule the model dropped --------------------------


def test_a_rejection_carrying_a_broadcast_hash_fails_the_negative_checks() -> None:
    """The model may admit a failed settlement with a hash; a rejected *invalid*
    payment still must not have been broadcast."""
    from x402_conformance.active import run_active_checks

    results = run_active_checks(RES, SIGNER, transport=pending_server(_pending(H1)))
    tampered = next(r for r in results if r.check_id == "RS-NEG-003")
    assert tampered.status is Status.FAIL
    assert "broadcast transaction" in tampered.detail
