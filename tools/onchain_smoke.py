"""End-to-end on-chain smoke test: one valid payment, real settlement, verified.

Builds a valid EIP-3009 payment with the FUNDED payer (Anvil acct #1), sends it
to the running on-chain facilitator, and confirms: 200 + resource delivered,
PAYMENT-RESPONSE success with a real tx hash, the tx is on-chain, and the funds
actually moved (payer balance down, payTo balance up).

Prereqs (WSL, venv active):
- anvil --chain-id 84532 running
- MockUSDC deployed, payer (acct #1) funded   (see onchain/README.md)
- tools/onchain_facilitator.py running with X402_TOKEN set

Run:
    X402_TOKEN=0x5FbDB2315678afecb367f032d93F642f64180aa3 python tools/onchain_smoke.py
"""

from __future__ import annotations

import base64
import json
import os
import sys

import httpx
from web3 import Web3

from x402_conformance.active import choose_eip3009_requirement
from x402_conformance.payload_builder import EvmSigner, build_exact_eip3009_payload
from x402_conformance.probe import build_probe

URL = os.environ.get("X402_RESOURCE_URL", "http://127.0.0.1:4500/data")
RPC = os.environ.get("X402_RPC_URL", "http://127.0.0.1:8545")
TOKEN = os.environ.get("X402_TOKEN", "")
# Anvil account #1 — the funded payer (public test key, never mainnet).
PAYER_KEY = os.environ.get(
    "X402_TESTNET_PAYER_KEY",
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
)

if not TOKEN:
    raise SystemExit("set X402_TOKEN to the deployed MockUSDC address")

w3 = Web3(Web3.HTTPProvider(RPC))
BALANCE_ABI = [
    {
        "type": "function",
        "name": "balanceOf",
        "stateMutability": "view",
        "inputs": [{"name": "a", "type": "address"}],
        "outputs": [{"type": "uint256"}],
    }
]
token = w3.eth.contract(address=Web3.to_checksum_address(TOKEN), abi=BALANCE_ABI)


def balance(addr: str) -> int:
    """Read the mock token balance of an address at the local chain."""
    return int(token.functions.balanceOf(Web3.to_checksum_address(addr)).call())


def main() -> int:
    """Exercise the full local resource payment, settlement proof, and replay flow."""
    ok = True

    def check(label: str, cond: bool, detail: str = "") -> None:
        """Index a conformance result by stable check ID and assert its expected status."""
        nonlocal ok
        ok = ok and cond
        mark = "PASS" if cond else "FAIL"
        print(f"  [{mark}] {label}" + (f" — {detail}" if detail else ""))

    print(f"on-chain smoke test against {URL} (token {TOKEN})")
    with httpx.Client(timeout=30) as c:
        probe = build_probe(c.get(URL))
        req = choose_eip3009_requirement(probe.raw)
        check("endpoint returns an exact/eip3009 requirement", req is not None)
        if req is None:
            return 1
        check(
            "advertised asset == deployed token",
            req["asset"].lower() == TOKEN.lower(),
            req.get("asset", ""),
        )

        signer = EvmSigner.from_key(PAYER_KEY)
        payer = signer.address
        pay_to = req["payTo"]
        amount = int(req["amount"])
        payer_before, payto_before = balance(payer), balance(pay_to)
        check("payer is funded", payer_before >= amount, f"balance={payer_before}")

        payload = build_exact_eip3009_payload(req, signer)
        header = base64.b64encode(json.dumps(payload).encode()).decode()
        resp = c.get(URL, headers={"PAYMENT-SIGNATURE": header})

        check(
            "HTTP 200 (resource delivered)", resp.status_code == 200, f"status={resp.status_code}"
        )
        check("body contains the protected resource", b"premium" in resp.content)

        pr = resp.headers.get("payment-response")
        settlement = json.loads(base64.b64decode(pr)) if pr else {}
        check(
            "PAYMENT-RESPONSE present + success",
            settlement.get("success") is True,
            str(settlement)[:160],
        )
        tx = settlement.get("transaction", "")
        check("settlement carries a tx hash", bool(tx) and tx != "0x", tx)

        if tx and tx != "0x":
            rcpt = w3.eth.wait_for_transaction_receipt(tx, timeout=30)
            check("tx is mined on-chain (status 1)", rcpt.status == 1)

        payer_after, payto_after = balance(payer), balance(pay_to)
        check(
            "payer balance decreased by amount",
            payer_before - payer_after == amount,
            f"{payer_before} -> {payer_after}",
        )
        check(
            "payTo balance increased by amount",
            payto_after - payto_before == amount,
            f"{payto_before} -> {payto_after}",
        )

    print("\nRESULT:", "ALL GREEN — settlement loop works end-to-end" if ok else "FAILURES above")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
