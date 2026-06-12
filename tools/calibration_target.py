"""A verify-capable x402 resource server for calibrating the active (RS-NEG) checks.

This is a *reference target*: it validates payments using the x402 SDK's own
EIP-712 digest (`hash_eip3009_authorization`) plus the same scheme/recipient/
amount/timing rules as the SDK facilitator's `verify`
(`x402/mechanisms/evm/exact/facilitator.py`). It omits only the RPC-bound steps
(on-chain balance, contract `get_code`, transfer simulation) — which the
negative cases never reach.

Because the suite signs payments *independently* (eth-account) and this target
verifies with the *SDK digest primitive*, a green `--active` run here is a
genuine cross-implementation calibration, not a self-check.

Usage:
    python tools/calibration_target.py [port]                 # correct server (default 4500)
    python tools/calibration_target.py 4500 --bug-no-amount   # drops the amount check
    python tools/calibration_target.py 4500 --bug-no-signature

Bug modes for the 2026-06-12 features (each must be CAUGHT by one check):
    --bug-leak           # echoes the resource marker in the rejection body  -> RS-SEC-009 / --resource-marker
    --bug-crash-huge     # returns 500 on a 2^256-1 amount instead of rejecting -> RS-SEC-011
    --bug-bad-checksum   # advertises a mixed-case asset with a broken EIP-55 checksum -> RS-PR-008

Then:
    x402-conformance check http://127.0.0.1:4500/data --active
    # correct server -> every RS-NEG / RS-SEC-010 / RS-SEC-011 check PASS

    x402-conformance check http://127.0.0.1:4500/data --active \
        --resource-marker x402-calib-marker-7f3a   # the RESOURCE_MARKER below

Requires the x402 SDK and eth-account (dev/calibration only).
"""

from __future__ import annotations

import base64
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from eth_account import Account

# SDK primitive: the spec-critical EIP-712 digest. Using the SDK here (while the
# suite signs independently) is what makes the calibration non-circular.
from x402.mechanisms.evm.eip712 import hash_eip3009_authorization
from x402.mechanisms.evm.types import ExactEIP3009Authorization

REQ = {
    "scheme": "exact",
    "network": "eip155:84532",
    "amount": "10000",
    "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
    "maxTimeoutSeconds": 60,
    "extra": {"name": "USDC", "version": "2"},
}
CHAIN_ID = 84532

# A unique token that lives only in the paid resource. The correct server never
# emits it on a rejection; `--bug-leak` does, so `--resource-marker` catches it.
RESOURCE_MARKER = "x402-calib-marker-7f3a"

def _break_checksum(addr: str) -> str:
    """Flip the case of the first hex *letter* (skipping '0x'): keeps the address
    well-formed and mixed-case but makes its EIP-55 checksum invalid. Robust
    regardless of which nibble the address ends on."""
    chars = list(addr)
    for i in range(2, len(chars)):
        if chars[i].isalpha():
            chars[i] = chars[i].swapcase()
            break
    return "".join(chars)


# A mixed-case asset with a deliberately broken EIP-55 checksum. `--bug-bad-checksum`
# advertises it so RS-PR-008 has something to catch.
BAD_CHECKSUM_ASSET = _break_checksum(REQ["asset"])

SUPPORTED = {
    "kinds": [{"x402Version": 2, "scheme": "exact", "network": REQ["network"]}],
    "extensions": [],
    "signers": {"eip155:*": ["0x0000000000000000000000000000000000000001"]},
}


def _verify_payload(payload: dict, bugs: set) -> dict:
    """Mirror the resource-server validation; return a VerifyResponse dict."""
    try:
        auth = payload["payload"]["authorization"]
        signature = payload["payload"]["signature"]
    except Exception:
        return {"isValid": False, "invalidReason": "invalid_payload"}
    if "recipient" not in bugs and str(auth.get("to", "")).lower() != REQ["payTo"].lower():
        return {"isValid": False, "invalidReason": "invalid_exact_evm_payload_recipient_mismatch",
                "payer": auth.get("from")}
    if "amount" not in bugs and int(auth.get("value", -1)) != int(REQ["amount"]):
        return {"isValid": False,
                "invalidReason": "invalid_exact_evm_payload_authorization_value_mismatch",
                "payer": auth.get("from")}
    now = int(time.time())
    if "time" not in bugs and not (int(auth["validAfter"]) <= now <= int(auth["validBefore"]) - 6):
        return {"isValid": False, "invalidReason": "invalid_exact_evm_payload_authorization_valid_before",
                "payer": auth.get("from")}
    if "signature" not in bugs and not _signature_recovers(auth, signature):
        return {"isValid": False, "invalidReason": "invalid_exact_evm_payload_signature",
                "payer": auth.get("from")}
    return {"isValid": True, "payer": auth["from"]}


def payment_required(port: int, bugs: set[str] | None = None) -> dict:
    req = dict(REQ)
    if bugs and "bad-checksum" in bugs:
        req["asset"] = BAD_CHECKSUM_ASSET  # RS-PR-008: mixed-case, invalid checksum
    return {
        "x402Version": 2,
        "resource": {"url": f"http://127.0.0.1:{port}/data"},
        "accepts": [req],
        "extensions": {},
    }


def _b64(obj: dict) -> str:
    return base64.b64encode(json.dumps(obj).encode()).decode()


def _signature_recovers(auth: dict, signature: str) -> bool:
    """Verify the EIP-3009 signature recovers to `from`, using the SDK digest."""
    sdk_auth = ExactEIP3009Authorization(
        from_address=auth["from"], to=auth["to"], value=str(auth["value"]),
        valid_after=str(auth["validAfter"]), valid_before=str(auth["validBefore"]),
        nonce=auth["nonce"],
    )
    digest = hash_eip3009_authorization(
        sdk_auth, CHAIN_ID, REQ["asset"], REQ["extra"]["name"], REQ["extra"]["version"]
    )
    try:
        return Account._recover_hash(digest, signature=signature) == auth["from"]
    except Exception:
        return False


def make_handler(bugs: set[str], port: int) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def _send(self, code: int, headers: dict | None = None, body: bytes = b"") -> None:
            self.send_response(code)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _reject(self, reason: str) -> None:
            # A correct server never returns the resource on a rejection. The
            # `--bug-leak` variant echoes the marker in the error body so that
            # `--resource-marker` (RS-SEC-009 path) has something to catch.
            body = b""
            if "leak" in bugs:
                body = json.dumps({"error": reason, "preview": f"premium {RESOURCE_MARKER}"}).encode()
            self._send(402, {"PAYMENT-RESPONSE": _b64(
                {"success": False, "errorReason": reason, "transaction": "", "network": REQ["network"]}
            )}, body)

        def do_GET(self) -> None:  # noqa: N802
            if self.path.rstrip("/").endswith("/supported"):
                self._send(200, {"Content-Type": "application/json"}, json.dumps(SUPPORTED).encode())
                return
            sig = self.headers.get("PAYMENT-SIGNATURE")
            if sig is None:
                self._send(402, {"PAYMENT-REQUIRED": _b64(payment_required(port, bugs))}, b"{}")
                return
            try:
                payload = json.loads(base64.b64decode(sig, validate=True))
                auth = payload["payload"]["authorization"]
                signature = payload["payload"]["signature"]
            except Exception:
                self._send(400)
                return

            # RS-SEC-011: a robust server rejects an extreme amount cleanly. The
            # `--bug-crash-huge` variant 500s on it instead (the bug to catch).
            if "crash-huge" in bugs and int(auth.get("value", 0)) > 10**30:
                self._send(500)
                return

            # Same validation order as SDK facilitator `_verify` (RPC steps omitted).
            if "recipient" not in bugs and str(auth.get("to", "")).lower() != REQ["payTo"].lower():
                return self._reject("invalid_exact_evm_payload_recipient_mismatch")
            if "amount" not in bugs and int(auth.get("value", -1)) != int(REQ["amount"]):
                return self._reject("invalid_exact_evm_payload_authorization_value_mismatch")
            now = int(time.time())
            if "time" not in bugs:
                if int(auth["validBefore"]) < now + 6:
                    return self._reject("invalid_exact_evm_payload_authorization_valid_before")
                if int(auth["validAfter"]) > now:
                    return self._reject("invalid_exact_evm_payload_authorization_valid_after")
            if "signature" not in bugs and not _signature_recovers(auth, signature):
                return self._reject("invalid_exact_evm_payload_signature")

            paid = json.dumps({"data": "premium", "secret": RESOURCE_MARKER}).encode()
            self._send(200, {"PAYMENT-RESPONSE": _b64(
                {"success": True, "transaction": "0x" + "ab" * 32, "network": REQ["network"],
                 "payer": auth["from"]}
            )}, paid)

        def do_POST(self) -> None:  # noqa: N802
            if not self.path.rstrip("/").endswith("/verify"):
                self._send(404)
                return
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length))
                payload = body["paymentPayload"]
            except Exception:
                self._send(200, {"Content-Type": "application/json"},
                           json.dumps({"isValid": False, "invalidReason": "invalid_payload"}).encode())
                return
            result = _verify_payload(payload, bugs)
            self._send(200, {"Content-Type": "application/json"}, json.dumps(result).encode())

        def log_message(self, *a: object) -> None:
            pass

    return Handler


if __name__ == "__main__":
    port = 4500
    bugs: set[str] = set()
    for a in sys.argv[1:]:
        if a.startswith("--bug-no-"):
            bugs.add(a.removeprefix("--bug-no-"))      # drop a validation step
        elif a.startswith("--bug-"):
            bugs.add(a.removeprefix("--bug-"))          # inject a behavioural bug
        elif a.isdigit():
            port = int(a)
    label = "correct" if not bugs else f"BUGGY (missing: {', '.join(sorted(bugs))})"
    print(f"calibration target on http://127.0.0.1:{port}/data  [{label}]")
    HTTPServer(("127.0.0.1", port), make_handler(bugs, port)).serve_forever()
