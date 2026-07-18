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

from x402_conformance import safety
from x402_conformance.active import run_payment_checks
from x402_conformance.checks import Status
from x402_conformance.checks import payment as payment_mod
from x402_conformance.payload_builder import EvmSigner

TARGET = "http://resource.example/data"
REQ = VALID_PAYMENT_REQUIRED["accepts"][0]
SIGNER = EvmSigner.from_key("0x" + "44" * 32)
RPC = "http://rpc.local"
_VERIFY_TX_ONCHAIN = payment_mod._verify_tx_onchain


@pytest.fixture(autouse=True)
def safe_funded_rpc(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep offline payment tests behind the mandatory RPC safety boundary."""

    monkeypatch.setattr(safety, "read_rpc_chain_id", lambda _url: 84532)
    monkeypatch.setattr(payment_mod, "_read_token_balance", lambda *a: 10**9)
    monkeypatch.setattr(
        payment_mod,
        "_verify_tx_onchain",
        lambda *a, **kw: (Status.SKIP, "offline test: receipt verification mocked"),
    )


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
    results = run_payment_checks(TARGET, SIGNER, rpc_url=RPC, transport=settling_server())
    assert by_id(results, "RS-PAY-001").status == Status.PASS
    assert by_id(results, "RS-PAY-002").status == Status.PASS
    assert by_id(results, "RS-PAY-003").status == Status.PASS
    assert by_id(results, "RS-PAY-004").status == Status.SKIP
    assert by_id(results, "RS-SEC-001").status == Status.PASS
    assert by_id(results, "RS-SEC-002").status == Status.PASS


def test_no_nonce_tracking_caught_by_replay_and_race() -> None:
    results = run_payment_checks(
        TARGET, SIGNER, rpc_url=RPC, transport=settling_server(track_nonces=False)
    )
    assert by_id(results, "RS-PAY-001").status == Status.PASS
    assert by_id(results, "RS-SEC-001").status == Status.FAIL
    assert by_id(results, "RS-SEC-002").status == Status.FAIL  # multiple concurrent settles


def test_success_but_empty_tx_is_caught() -> None:
    bad = {"success": True, "transaction": "", "network": REQ["network"], "payer": SIGNER.address}
    results = run_payment_checks(
        TARGET, SIGNER, rpc_url=RPC, transport=settling_server(settlement=bad)
    )
    assert by_id(results, "RS-PAY-002").status == Status.FAIL


def test_rejected_valid_payment_is_caught() -> None:
    fail = {
        "success": False,
        "errorReason": "insufficient_funds",
        "transaction": "",
        "network": REQ["network"],
    }
    results = run_payment_checks(
        TARGET, SIGNER, rpc_url=RPC, transport=settling_server(settlement=fail, status=402)
    )
    assert by_id(results, "RS-PAY-001").status == Status.FAIL


def test_wrong_payer_in_settlement_is_caught() -> None:
    wrong = {
        "success": True,
        "transaction": "0x" + "cd" * 32,
        "network": REQ["network"],
        "payer": "0x000000000000000000000000000000000000dEaD",
    }
    results = run_payment_checks(
        TARGET, SIGNER, rpc_url=RPC, transport=settling_server(settlement=wrong)
    )
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
        TARGET, SIGNER, rpc_url=RPC, transport=httpx.MockTransport(handler)
    )
    assert all(r.status == Status.SKIP for r in results)
    assert "insufficient" in by_id(results, "RS-PAY-001").detail
    assert sends["n"] == 0  # no funds were moved


def test_balance_precheck_does_not_block_when_funded(monkeypatch: pytest.MonkeyPatch) -> None:
    # A funded signer (balance >= amount) proceeds through the normal happy path.
    monkeypatch.setattr(payment_mod, "_read_token_balance", lambda *a: 10**9)
    results = run_payment_checks(TARGET, SIGNER, rpc_url=RPC, transport=settling_server())
    assert by_id(results, "RS-PAY-001").status == Status.PASS


def test_balance_precheck_fails_closed_when_unreadable(monkeypatch: pytest.MonkeyPatch) -> None:
    sends = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("PAYMENT-SIGNATURE") is None:
            return httpx.Response(
                402, headers={"PAYMENT-REQUIRED": encode_header(VALID_PAYMENT_REQUIRED)}
            )
        sends["n"] += 1
        return httpx.Response(500)

    monkeypatch.setattr(payment_mod, "_read_token_balance", lambda *a: None)
    results = run_payment_checks(
        TARGET, SIGNER, rpc_url=RPC, transport=httpx.MockTransport(handler)
    )
    assert all(r.status == Status.ERROR for r in results)
    assert "failed closed" in by_id(results, "RS-PAY-001").detail
    assert sends["n"] == 0


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

    results = run_payment_checks(
        TARGET, SIGNER, rpc_url=RPC, transport=httpx.MockTransport(handler)
    )
    assert all(r.status == Status.SKIP for r in results)


def _transfer_log(
    *,
    asset: str = REQ["asset"],
    payer: str = SIGNER.address,
    pay_to: str = REQ["payTo"],
    amount: int = int(REQ["amount"]),
) -> dict:
    return {
        "address": asset,
        "topics": [
            bytes.fromhex(payment_mod._TRANSFER_TOPIC[2:]),
            bytes.fromhex(payment_mod._address_topic(payer)[2:]),
            bytes.fromhex(payment_mod._address_topic(pay_to)[2:]),
        ],
        "data": amount.to_bytes(32, "big"),
    }


def test_transfer_log_proves_asset_payer_payto_and_amount() -> None:
    status, detail = payment_mod._verify_transfer_logs(
        {"logs": [_transfer_log()]},
        asset=REQ["asset"],
        payer=SIGNER.address,
        pay_to=REQ["payTo"],
        amount=int(REQ["amount"]),
    )
    assert status == Status.PASS
    assert "proven on-chain" in detail


@pytest.mark.parametrize(
    ("logs", "expected"),
    [
        ([], "found 0"),
        ([_transfer_log(asset="0x" + "99" * 20)], "found 0"),
        ([_transfer_log(pay_to="0x" + "88" * 20)], "recipient"),
        ([_transfer_log(amount=1)], "amount"),
        ([_transfer_log(), _transfer_log()], "found 2"),
    ],
)
def test_transfer_log_rejects_unrelated_or_ambiguous_outcomes(
    logs: list[dict], expected: str
) -> None:
    status, detail = payment_mod._verify_transfer_logs(
        {"logs": logs},
        asset=REQ["asset"],
        payer=SIGNER.address,
        pay_to=REQ["payTo"],
        amount=int(REQ["amount"]),
    )
    assert status == Status.FAIL
    assert expected in detail


def test_onchain_verifier_rejects_reverted_receipt(monkeypatch: pytest.MonkeyPatch) -> None:
    import web3

    class FakeEth:
        def get_transaction_receipt(self, _tx: str) -> dict:
            return {"status": 0, "blockNumber": 3, "logs": []}

    class FakeWeb3:
        HTTPProvider = staticmethod(lambda url: url)

        def __init__(self, _provider: object) -> None:
            self.eth = FakeEth()

    monkeypatch.setattr(web3, "Web3", FakeWeb3)
    status, detail = _VERIFY_TX_ONCHAIN(
        "http://rpc.local",
        "0x" + "ab" * 32,
        asset=REQ["asset"],
        payer=SIGNER.address,
        pay_to=REQ["payTo"],
        amount=int(REQ["amount"]),
    )
    assert status == Status.FAIL
    assert "reverted" in detail


def test_missing_settlement_payer_is_not_accepted() -> None:
    settlement = {
        "success": True,
        "transaction": "0x" + "cd" * 32,
        "network": REQ["network"],
    }
    results = run_payment_checks(
        TARGET, SIGNER, rpc_url=RPC, transport=settling_server(settlement=settlement)
    )
    assert by_id(results, "RS-PAY-003").status == Status.FAIL
    assert "identify payer" in by_id(results, "RS-PAY-003").detail
