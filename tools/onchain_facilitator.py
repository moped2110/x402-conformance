"""A real x402 facilitator + resource server that settles ON-CHAIN against Anvil.

This is the on-chain successor to ``calibration_target.py``: instead of faking
settlement, it verifies the EIP-3009 payment off-chain (signature/recipient/
amount/time), checks the payer's balance on-chain, and then SETTLES by calling
``transferWithAuthorization`` on the MockUSDC token — a real transaction, real
funds moving, a real tx hash in the PAYMENT-RESPONSE.

Roles (Anvil defaults, public test keys — never mainnet):
- facilitator submitter (pays gas): Anvil acct #0
- payer (EIP-3009 signer, funded with MockUSDC): Anvil acct #1
- payTo (merchant): Anvil acct #2

Config via env (defaults match onchain/README.md):
    X402_RPC_URL       default http://127.0.0.1:8545
    X402_TOKEN         MockUSDC address (required, e.g. 0x5FbD...80aa3)
    X402_FAC_KEY       facilitator submitter key (Anvil acct #0)
    X402_PAY_TO        merchant address (Anvil acct #2)
    X402_AMOUNT        required amount in atomic units (default 10000 = 0.01 USDC)
    X402_PORT          default 4500

Run (in WSL, venv active, web3 installed):
    X402_TOKEN=0x5FbDB2315678afecb367f032d93F642f64180aa3 \
    python tools/onchain_facilitator.py
"""

from __future__ import annotations

import base64
import json
import os
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from web3 import Web3

RPC_URL = os.environ.get("X402_RPC_URL", "http://127.0.0.1:8545")
TOKEN = os.environ.get("X402_TOKEN", "")
FAC_KEY = os.environ.get(
    "X402_FAC_KEY", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
)
PAY_TO = os.environ.get("X402_PAY_TO", "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC")
AMOUNT = os.environ.get("X402_AMOUNT", "10000")
PORT = int(os.environ.get("X402_PORT", "4500"))
CHAIN_ID = 84532
TOKEN_NAME, TOKEN_VERSION = "USDC", "2"

if not TOKEN:
    raise SystemExit("set X402_TOKEN to the deployed MockUSDC address")

ABI = [
    {"type": "function", "name": "balanceOf", "stateMutability": "view",
     "inputs": [{"name": "a", "type": "address"}], "outputs": [{"type": "uint256"}]},
    {"type": "function", "name": "authorizationState", "stateMutability": "view",
     "inputs": [{"name": "a", "type": "address"}, {"name": "n", "type": "bytes32"}],
     "outputs": [{"type": "bool"}]},
    {"type": "function", "name": "transferWithAuthorization", "stateMutability": "nonpayable",
     "inputs": [
         {"name": "from", "type": "address"}, {"name": "to", "type": "address"},
         {"name": "value", "type": "uint256"}, {"name": "validAfter", "type": "uint256"},
         {"name": "validBefore", "type": "uint256"}, {"name": "nonce", "type": "bytes32"},
         {"name": "signature", "type": "bytes"}],
     "outputs": []},
]

w3 = Web3(Web3.HTTPProvider(RPC_URL))
fac = w3.eth.account.from_key(FAC_KEY)
token = w3.eth.contract(address=Web3.to_checksum_address(TOKEN), abi=ABI)

REQ = {
    "scheme": "exact", "network": f"eip155:{CHAIN_ID}", "amount": AMOUNT,
    "asset": Web3.to_checksum_address(TOKEN), "payTo": Web3.to_checksum_address(PAY_TO),
    "maxTimeoutSeconds": 60, "extra": {"name": TOKEN_NAME, "version": TOKEN_VERSION},
}
SUPPORTED = {
    "kinds": [{"x402Version": 2, "scheme": "exact", "network": REQ["network"]}],
    "extensions": [], "signers": {"eip155:*": [fac.address]},
}


def _b64(obj: dict) -> str:
    return base64.b64encode(json.dumps(obj).encode()).decode()


def payment_required() -> dict:
    return {"x402Version": 2, "resource": {"url": f"http://127.0.0.1:{PORT}/data"},
            "accepts": [REQ], "extensions": {}}


def _verify_offchain(auth: dict) -> str | None:
    """Off-chain checks (recipient/amount/time). Returns an error code or None."""
    if str(auth.get("to", "")).lower() != REQ["payTo"].lower():
        return "invalid_exact_evm_payload_recipient_mismatch"
    if int(auth.get("value", -1)) != int(REQ["amount"]):
        return "invalid_exact_evm_payload_authorization_value_mismatch"
    now = int(time.time())
    if int(auth["validBefore"]) <= now:
        return "invalid_exact_evm_payload_authorization_valid_before"
    if int(auth["validAfter"]) >= now:
        return "invalid_exact_evm_payload_authorization_valid_after"
    return None


def _check_balance(auth: dict) -> str | None:
    bal = token.functions.balanceOf(Web3.to_checksum_address(auth["from"])).call()
    if bal < int(auth["value"]):
        return "insufficient_funds"
    return None


def verify(auth: dict) -> dict:
    """Off-chain validation + on-chain balance (the signature is enforced on-chain at settle)."""
    err = _verify_offchain(auth) or _check_balance(auth)
    if err:
        return {"isValid": False, "invalidReason": err, "payer": auth.get("from")}
    return {"isValid": True, "payer": auth["from"]}


def settle(auth: dict, signature: str) -> dict:
    """Submit transferWithAuthorization on-chain. Returns a SettlementResponse dict."""
    err = _verify_offchain(auth) or _check_balance(auth)
    if err:
        return {"success": False, "errorReason": err, "transaction": "",
                "network": REQ["network"], "payer": auth.get("from")}
    try:
        tx = token.functions.transferWithAuthorization(
            Web3.to_checksum_address(auth["from"]), Web3.to_checksum_address(auth["to"]),
            int(auth["value"]), int(auth["validAfter"]), int(auth["validBefore"]),
            bytes.fromhex(auth["nonce"][2:]), bytes.fromhex(signature[2:]),
        ).build_transaction({
            "from": fac.address, "nonce": w3.eth.get_transaction_count(fac.address),
            "gas": 200000, "gasPrice": w3.eth.gas_price, "chainId": CHAIN_ID,
        })
        signed = fac.sign_transaction(tx)
        raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
        h = w3.eth.send_raw_transaction(raw)
        tx_hash = Web3.to_hex(h)  # always 0x-prefixed
        receipt = w3.eth.wait_for_transaction_receipt(h, timeout=30)
        if receipt.status == 1:
            return {"success": True, "transaction": tx_hash,
                    "network": REQ["network"], "payer": auth["from"]}
        return {"success": False, "errorReason": "invalid_transaction_state",
                "transaction": "", "network": REQ["network"], "payer": auth["from"]}
    except Exception as exc:
        return {"success": False, "errorReason": "unexpected_settle_error",
                "transaction": "", "network": REQ["network"], "payer": auth.get("from"),
                "message": str(exc)[:200]}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, headers: dict | None = None, body: bytes = b"") -> None:
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path.rstrip("/").endswith("/supported"):
            self._send(200, {"Content-Type": "application/json"}, json.dumps(SUPPORTED).encode())
            return
        sig = self.headers.get("PAYMENT-SIGNATURE")
        if sig is None:
            self._send(402, {"PAYMENT-REQUIRED": _b64(payment_required())}, b"{}")
            return
        try:
            payload = json.loads(base64.b64decode(sig, validate=True))
            auth = payload["payload"]["authorization"]
            signature = payload["payload"]["signature"]
        except Exception:
            self._send(400)
            return
        result = settle(auth, signature)
        if result["success"]:
            self._send(200, {"PAYMENT-RESPONSE": _b64(result)}, b'{"data": "premium"}')
        else:
            self._send(402, {"PAYMENT-RESPONSE": _b64(result)})

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.rstrip("/")
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length))
            payload = body["paymentPayload"]
            auth = payload["payload"]["authorization"]
            signature = payload["payload"]["signature"]
        except Exception:
            self._send(200, {"Content-Type": "application/json"},
                       json.dumps({"isValid": False, "invalidReason": "invalid_payload"}).encode())
            return
        if path.endswith("/verify"):
            self._send(200, {"Content-Type": "application/json"}, json.dumps(verify(auth)).encode())
        elif path.endswith("/settle"):
            self._send(200, {"Content-Type": "application/json"},
                       json.dumps(settle(auth, signature)).encode())
        else:
            self._send(404)

    def log_message(self, *a: object) -> None:
        pass


if __name__ == "__main__":
    print(f"on-chain facilitator on http://127.0.0.1:{PORT}")
    print(f"  RPC      {RPC_URL} (chainId {CHAIN_ID}, connected: {w3.is_connected()})")
    print(f"  token    {REQ['asset']}")
    print(f"  payTo    {REQ['payTo']}  amount {REQ['amount']}")
    print(f"  fac/gas  {fac.address}")
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
