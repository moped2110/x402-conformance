"""Tests for the FA facilitator checks against correct and buggy mock facilitators."""

from __future__ import annotations

import json

import httpx
import pytest

pytest.importorskip("eth_account")

from conftest import VALID_PAYMENT_REQUIRED, encode_header

from x402_conformance import safety
from x402_conformance.checks import Status
from x402_conformance.checks.facilitator import run_facilitator_checks
from x402_conformance.payload_builder import EvmSigner

FAC = "http://facilitator.example"
RES = "http://resource.example/data"
REQ = VALID_PAYMENT_REQUIRED["accepts"][0]
SIGNER = EvmSigner.from_key("0x" + "33" * 32)


@pytest.fixture(autouse=True)
def _safe_rpc_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(safety, "read_rpc_chain_id", lambda _url: 84532)
    monkeypatch.setattr(
        "x402_conformance.checks.payment._verify_tx_onchain",
        lambda *_a, **_k: (Status.PASS, "matching Transfer event"),
    )


GOOD_SUPPORTED = {
    "kinds": [{"x402Version": 2, "scheme": "exact", "network": "eip155:84532"}],
    "extensions": [],
    "signers": {"eip155:*": ["0x0000000000000000000000000000000000000001"]},
}


def make_facilitator(
    *,
    supported: dict | None = None,
    verify_buggy: bool = False,
    settle_no_nonce_check: bool = False,
    verify_wrong_type: bool = False,
    settle_wrong_type: bool = False,
    second_settle_non_json: bool = False,
    second_settle_transport_error: bool = False,
) -> httpx.MockTransport:
    body = GOOD_SUPPORTED if supported is None else supported
    used_nonces: set = set()
    settle_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "GET" and path == "/data":
            return httpx.Response(
                402, headers={"PAYMENT-REQUIRED": encode_header(VALID_PAYMENT_REQUIRED)}
            )
        if request.method == "GET" and path == "/supported":
            return httpx.Response(200, json=body)
        if request.method == "POST" and path == "/verify":
            payload = json.loads(request.content)
            auth = payload["paymentPayload"]["payload"]["authorization"]
            req = payload["paymentRequirements"]
            if verify_wrong_type:
                return httpx.Response(200, json={"isValid": "false", "invalidReason": "x"})
            valid = int(auth["value"]) == int(req["amount"])
            if verify_buggy or valid:
                return httpx.Response(200, json={"isValid": True, "payer": auth["from"]})
            return httpx.Response(
                200,
                json={
                    "isValid": False,
                    "invalidReason": "invalid_exact_evm_payload_authorization_value_mismatch",
                    "payer": auth["from"],
                },
            )
        if request.method == "POST" and path == "/settle":
            nonlocal settle_calls
            settle_calls += 1
            if settle_calls == 2 and second_settle_transport_error:
                raise httpx.ConnectError("connection reset during second settle")
            if settle_calls == 2 and second_settle_non_json:
                return httpx.Response(200, text="not json")
            if settle_wrong_type:
                return httpx.Response(
                    200,
                    json={
                        "success": "true",
                        "transaction": "0x" + "ef" * 32,
                        "network": REQ["network"],
                    },
                )
            payload = json.loads(request.content)
            auth = payload["paymentPayload"]["payload"]["authorization"]
            req = payload["paymentRequirements"]
            net = req["network"]
            if int(auth["value"]) != int(req["amount"]):
                return httpx.Response(
                    200,
                    json={
                        "success": False,
                        "transaction": "",
                        "errorReason": "invalid_exact_evm_payload_authorization_value_mismatch",
                        "network": net,
                        "payer": auth["from"],
                    },
                )
            nonce = auth["nonce"]
            if not settle_no_nonce_check and nonce in used_nonces:
                return httpx.Response(
                    200,
                    json={
                        "success": False,
                        "transaction": "",
                        "errorReason": "invalid_transaction_state",
                        "network": net,
                        "payer": auth["from"],
                    },
                )
            used_nonces.add(nonce)
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "transaction": "0x" + "ef" * 32,
                    "network": net,
                    "payer": auth["from"],
                },
            )
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def by_id(results, cid):
    return next(r for r in results if r.check_id == cid)


def test_correct_facilitator_supported_and_verify() -> None:
    results = run_facilitator_checks(
        FAC, resource_url=RES, signer=SIGNER, transport=make_facilitator()
    )
    assert by_id(results, "FA-SUP-001").status == Status.PASS
    assert by_id(results, "FA-SUP-002").status == Status.PASS
    assert by_id(results, "FA-VER-002").status == Status.PASS
    assert by_id(results, "FA-ERR-001").status == Status.PASS


def test_supported_missing_signers_fails() -> None:
    bad = {"kinds": GOOD_SUPPORTED["kinds"], "extensions": []}  # no signers
    results = run_facilitator_checks(FAC, transport=make_facilitator(supported=bad))
    assert by_id(results, "FA-SUP-001").status == Status.FAIL


def test_kind_non_caip2_fails() -> None:
    # A *v2* kind must use a CAIP-2 network; a legacy name is a fault for v2.
    bad = {
        "kinds": [{"x402Version": 2, "scheme": "exact", "network": "base-sepolia"}],
        "extensions": [],
        "signers": {},
    }
    results = run_facilitator_checks(FAC, transport=make_facilitator(supported=bad))
    assert by_id(results, "FA-SUP-002").status == Status.FAIL


def test_mixed_v1_v2_supported_passes() -> None:
    # A facilitator serving both protocol versions (the common case, e.g. x402-rs)
    # advertises a v1 kind with a legacy network NAME alongside a CAIP-2 v2 kind.
    # Both are conformant — FA-SUP-002 must not flag the v1 kind.
    mixed = {
        "kinds": [
            {"x402Version": 2, "scheme": "exact", "network": "eip155:84532"},
            {"x402Version": 1, "scheme": "exact", "network": "base-sepolia"},
        ],
        "extensions": [],
        "signers": {},
    }
    results = run_facilitator_checks(FAC, transport=make_facilitator(supported=mixed))
    assert by_id(results, "FA-SUP-002").status == Status.PASS


def test_unknown_version_kind_fails() -> None:
    bad = {
        "kinds": [{"x402Version": 3, "scheme": "exact", "network": "eip155:84532"}],
        "extensions": [],
        "signers": {},
    }
    results = run_facilitator_checks(FAC, transport=make_facilitator(supported=bad))
    assert by_id(results, "FA-SUP-002").status == Status.FAIL


def test_buggy_verify_accepts_underpayment_is_caught() -> None:
    results = run_facilitator_checks(
        FAC, resource_url=RES, signer=SIGNER, transport=make_facilitator(verify_buggy=True)
    )
    assert by_id(results, "FA-VER-002").status == Status.FAIL


def test_verify_wrong_wire_types_are_not_coerced() -> None:
    results = run_facilitator_checks(
        FAC, resource_url=RES, signer=SIGNER, transport=make_facilitator(verify_wrong_type=True)
    )
    assert by_id(results, "FA-VER-002").status == Status.FAIL


def test_no_resource_skips_verify_checks() -> None:
    results = run_facilitator_checks(FAC, transport=make_facilitator())
    assert by_id(results, "FA-VER-002").status == Status.SKIP
    assert by_id(results, "FA-ERR-001").status == Status.SKIP
    # SUP checks still run
    assert by_id(results, "FA-SUP-001").status == Status.PASS


# --- FA-SET (direct /settle, opt-in, nonce-aware) ---


def test_settle_group_skipped_without_flag() -> None:
    results = run_facilitator_checks(
        FAC, resource_url=RES, signer=SIGNER, transport=make_facilitator()
    )
    for cid in ("FA-SET-001", "FA-SET-002", "FA-SET-003"):
        assert by_id(results, cid).status == Status.SKIP


def test_settle_happy_and_double_settle_blocked() -> None:
    results = run_facilitator_checks(
        FAC,
        resource_url=RES,
        signer=SIGNER,
        allow_settle=True,
        rpc_url="http://rpc.local",
        transport=make_facilitator(),
    )
    assert by_id(results, "FA-SET-001").status == Status.PASS
    assert by_id(results, "FA-SET-002").status == Status.PASS
    assert by_id(results, "FA-SET-003").status == Status.PASS  # double-settle rejected


def test_settle_onchain_proof_failure_gates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "x402_conformance.checks.payment._verify_tx_onchain",
        lambda *_a, **_k: (Status.FAIL, "wrong token Transfer event"),
    )
    results = run_facilitator_checks(
        FAC,
        resource_url=RES,
        signer=SIGNER,
        allow_settle=True,
        rpc_url="http://rpc.local",
        transport=make_facilitator(),
    )
    proof = by_id(results, "FA-SET-001")
    assert proof.status == Status.FAIL
    assert "wrong token" in proof.detail


def test_settle_without_nonce_check_is_caught() -> None:
    results = run_facilitator_checks(
        FAC,
        resource_url=RES,
        signer=SIGNER,
        allow_settle=True,
        rpc_url="http://rpc.local",
        transport=make_facilitator(settle_no_nonce_check=True),
    )
    assert by_id(results, "FA-SET-003").status == Status.FAIL  # double-settle wrongly accepted


def test_second_settle_non_json_is_fail_not_replay_pass() -> None:
    results = run_facilitator_checks(
        FAC,
        resource_url=RES,
        signer=SIGNER,
        allow_settle=True,
        rpc_url="http://rpc.local",
        transport=make_facilitator(second_settle_non_json=True),
    )
    assert by_id(results, "FA-SET-003").status == Status.FAIL


def test_second_settle_transport_failure_propagates_as_unreachable() -> None:
    with pytest.raises(httpx.ConnectError):
        run_facilitator_checks(
            FAC,
            resource_url=RES,
            signer=SIGNER,
            allow_settle=True,
            rpc_url="http://rpc.local",
            transport=make_facilitator(second_settle_transport_error=True),
        )


def test_settle_wrong_wire_types_are_not_coerced() -> None:
    results = run_facilitator_checks(
        FAC,
        resource_url=RES,
        signer=SIGNER,
        allow_settle=True,
        rpc_url="http://rpc.local",
        transport=make_facilitator(settle_wrong_type=True),
    )
    assert by_id(results, "FA-SET-001").status == Status.FAIL
