"""Tests for RS-PAY (positive settlement) + RS-SEC-001/002 (replay/race), offline.

The real on-chain path is proven by tools/onchain_smoke.py and `check --pay`
against Anvil; here we verify the check LOGIC against a mocked settling server
that, like the real EIP-3009 token, tracks nonces (thread-safe).
"""

from __future__ import annotations

import base64
import json
import threading

import httpx
import pytest

pytest.importorskip("eth_account")

from conftest import VALID_PAYMENT_REQUIRED, encode_header

from x402_conformance.active import run_payment_checks
from x402_conformance.checks import Status
from x402_conformance.checks import payment as payment_mod
from x402_conformance.payload_builder import EvmSigner

TARGET = "http://resource.example/data"
REQ = VALID_PAYMENT_REQUIRED["accepts"][0]
SIGNER = EvmSigner.from_key("0x" + "44" * 32)


def by_id(results, cid):
    return next(r for r in results if r.check_id == cid)


def _enc(obj: dict) -> str:
    return base64.b64encode(json.dumps(obj).encode()).decode()


def settling_server(
    *,
    track_nonces: bool = True,
    settlement: dict | None = None,
    status: int = 200,
    body: bytes = b'{"data":"premium"}',
) -> httpx.MockTransport:
    """A settling resource server. Tracks nonces (thread-safe) like a real token."""
    used: set[str] = set()
    lock = threading.Lock()

    def handler(request: httpx.Request) -> httpx.Response:
        sig = request.headers.get("PAYMENT-SIGNATURE")
        if sig is None:
            return httpx.Response(
                402, headers={"PAYMENT-REQUIRED": encode_header(VALID_PAYMENT_REQUIRED)}
            )
        payload = json.loads(base64.b64decode(sig))
        nonce = payload["payload"]["authorization"]["nonce"]
        if track_nonces:
            with lock:
                fresh = nonce not in used
                if fresh:
                    used.add(nonce)
            if not fresh:
                fail = {
                    "success": False,
                    "errorReason": "invalid_transaction_state",
                    "transaction": "",
                    "network": REQ["network"],
                }
                return httpx.Response(402, headers={"PAYMENT-RESPONSE": _enc(fail)})
        if settlement is not None:
            return httpx.Response(
                status, headers={"PAYMENT-RESPONSE": _enc(settlement)}, content=body
            )
        ok = {
            "success": True,
            "transaction": "0x" + "cd" * 32,
            "network": REQ["network"],
            "payer": payload["payload"]["authorization"]["from"],
        }
        return httpx.Response(200, headers={"PAYMENT-RESPONSE": _enc(ok)}, content=body)

    return httpx.MockTransport(handler)


def test_happy_path_settles_delivers_blocks_replay_and_race() -> None:
    results = run_payment_checks(TARGET, SIGNER, transport=settling_server())
    assert by_id(results, "RS-PAY-001").status == Status.PASS
    assert by_id(results, "RS-PAY-002").status == Status.PASS
    assert by_id(results, "RS-PAY-003").status == Status.PASS
    assert by_id(results, "RS-PAY-004").status == Status.SKIP
    assert by_id(results, "RS-SEC-001").status == Status.PASS
    assert by_id(results, "RS-SEC-002").status == Status.PASS


def test_no_nonce_tracking_caught_by_replay_and_race() -> None:
    results = run_payment_checks(TARGET, SIGNER, transport=settling_server(track_nonces=False))
    assert by_id(results, "RS-PAY-001").status == Status.PASS
    assert by_id(results, "RS-SEC-001").status == Status.FAIL
    assert by_id(results, "RS-SEC-002").status == Status.FAIL  # multiple concurrent settles


def test_success_but_empty_tx_is_caught() -> None:
    bad = {"success": True, "transaction": "", "network": REQ["network"], "payer": SIGNER.address}
    results = run_payment_checks(TARGET, SIGNER, transport=settling_server(settlement=bad))
    assert by_id(results, "RS-PAY-002").status == Status.FAIL


def test_rejected_valid_payment_is_caught() -> None:
    fail = {
        "success": False,
        "errorReason": "insufficient_funds",
        "transaction": "",
        "network": REQ["network"],
    }
    results = run_payment_checks(
        TARGET, SIGNER, transport=settling_server(settlement=fail, status=402)
    )
    assert by_id(results, "RS-PAY-001").status == Status.FAIL


def test_wrong_payer_in_settlement_is_caught() -> None:
    wrong = {
        "success": True,
        "transaction": "0x" + "cd" * 32,
        "network": REQ["network"],
        "payer": "0x000000000000000000000000000000000000dEaD",
    }
    results = run_payment_checks(TARGET, SIGNER, transport=settling_server(settlement=wrong))
    assert by_id(results, "RS-PAY-003").status == Status.FAIL


def test_balance_precheck_skips_underfunded_without_paying(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Signer holds 0 tokens but the endpoint wants 10000 → the group must SKIP with a
    # clear reason and NEVER send a (doomed) payment when an --rpc-url is available.
    monkeypatch.setattr(payment_mod, "_read_token_balance", lambda *a: 0)
    sends = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("PAYMENT-SIGNATURE") is None:
            return httpx.Response(
                402, headers={"PAYMENT-REQUIRED": encode_header(VALID_PAYMENT_REQUIRED)}
            )
        sends["n"] += 1  # a payment attempt reached the server
        ok = {"success": True, "transaction": "0x" + "cd" * 32, "network": REQ["network"]}
        return httpx.Response(200, headers={"PAYMENT-RESPONSE": _enc(ok)}, content=b"x")

    results = run_payment_checks(
        TARGET, SIGNER, rpc_url="http://rpc.local", transport=httpx.MockTransport(handler)
    )
    assert all(r.status == Status.SKIP for r in results)
    assert "insufficient" in by_id(results, "RS-PAY-001").detail
    assert sends["n"] == 0  # no funds were moved


def test_balance_precheck_does_not_block_when_funded(monkeypatch: pytest.MonkeyPatch) -> None:
    # A funded signer (balance >= amount) proceeds through the normal happy path.
    monkeypatch.setattr(payment_mod, "_read_token_balance", lambda *a: 10**9)
    results = run_payment_checks(
        TARGET, SIGNER, rpc_url="http://rpc.local", transport=settling_server()
    )
    assert by_id(results, "RS-PAY-001").status == Status.PASS


def test_balance_precheck_skipped_when_unreadable(monkeypatch: pytest.MonkeyPatch) -> None:
    # An unreadable balance (None) must not block the run — proceed as before.
    monkeypatch.setattr(payment_mod, "_read_token_balance", lambda *a: None)
    results = run_payment_checks(
        TARGET, SIGNER, rpc_url="http://rpc.local", transport=settling_server()
    )
    assert by_id(results, "RS-PAY-001").status == Status.PASS


def test_no_eip3009_endpoint_skips_all() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        solana = {
            "x402Version": 2,
            "resource": {"url": TARGET},
            "accepts": [
                {
                    "scheme": "exact",
                    "network": "solana:x",
                    "amount": "1",
                    "asset": "x",
                    "payTo": "x",
                    "maxTimeoutSeconds": 60,
                }
            ],
        }
        return httpx.Response(402, headers={"PAYMENT-REQUIRED": encode_header(solana)})

    results = run_payment_checks(TARGET, SIGNER, transport=httpx.MockTransport(handler))
    assert all(r.status == Status.SKIP for r in results)
