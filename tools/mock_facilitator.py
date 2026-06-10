"""Minimal mock facilitator for local development and calibration runs.

Serves only ``GET /supported`` — enough for x402 resource servers (reference
SDK) to initialize and emit 402 responses. ``/verify`` and ``/settle`` are
deliberately absent: this mock must never be mistaken for a payment path.

Calibration finding (2026-06-09): the reference SDK requires per-kind
capability fields in ``extra`` that the core spec (§7.3) does not document:
- ``upto``             -> ``extra.facilitatorAddress``
- ``batch-settlement`` -> ``extra.receiverAuthorizer``

Usage:
    python tools/mock_facilitator.py [port]   # default 4099
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

EVM_NETWORK = "eip155:84532"  # Base Sepolia
DUMMY_ADDRESS = "0x0000000000000000000000000000000000000001"

SUPPORTED = {
    "kinds": [
        {"x402Version": 2, "scheme": "exact", "network": EVM_NETWORK},
        {
            "x402Version": 2,
            "scheme": "upto",
            "network": EVM_NETWORK,
            "extra": {"facilitatorAddress": DUMMY_ADDRESS},
        },
        {
            "x402Version": 2,
            "scheme": "batch-settlement",
            "network": EVM_NETWORK,
            "extra": {"receiverAuthorizer": DUMMY_ADDRESS},
        },
    ],
    "extensions": ["bazaar", "eip2612GasSponsoring", "erc20ApprovalGasSponsoring"],
    "signers": {"eip155:*": [DUMMY_ADDRESS]},
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
        if self.path.rstrip("/").endswith("/supported"):
            body = json.dumps(SUPPORTED).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args: object) -> None:  # silence
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 4099
    print(f"mock facilitator on http://127.0.0.1:{port} (GET /supported only)")
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
