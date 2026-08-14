"""TEST-ONLY fixture SUT for the opt-in PQC conformance profile."""

from __future__ import annotations

import base64
import copy
import json
from typing import Any

import httpx
from conftest import TARGET_URL, VALID_PAYMENT_REQUIRED, encode_header
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, mldsa

VERIFY_URL = "https://api.example.com/test-only/pqc/verify"


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _payload(receipt: dict[str, Any]) -> bytes:
    unsigned = copy.deepcopy(receipt)
    unsigned["sig_v2"]["classical"]["signature"] = ""
    unsigned["sig_v2"]["pqc"]["signature"] = ""
    return (
        b"PSV-RECEIPT-V2\x00"
        + json.dumps(unsigned, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
    )


class PQCFixtureSUT:
    """Ephemeral hybrid receipt issuer/verifier; never suitable for production."""

    def __init__(
        self,
        *,
        ignore_pqc: bool = False,
        allow_downgrade: bool = False,
        silent_downgrade: bool = False,
    ) -> None:
        self.classical = ec.generate_private_key(ec.SECP256R1())
        self.pqc = mldsa.MLDSA65PrivateKey.generate()
        self.ignore_pqc = ignore_pqc
        self.allow_downgrade = allow_downgrade
        self.silent_downgrade = silent_downgrade
        self.receipt = self._issue()
        self.capability = self._build_challenge()

    def _issue(self) -> dict[str, Any]:
        receipt: dict[str, Any] = {
            "transaction": "TEST-ONLY-transaction",
            "network": "eip155:31337",
            "amount": "100",
            "sig_v2": {
                "version": 2,
                "classical": {
                    "alg": "ECDSA-P256-SHA256",
                    "kid": "TEST-ONLY-classical",
                    "signature": "",
                },
                "pqc": {
                    "alg": "ML-DSA-65",
                    "kid": "TEST-ONLY-pqc",
                    "signature": "",
                },
            },
        }
        payload = _payload(receipt)
        receipt["sig_v2"]["classical"]["signature"] = _b64(
            self.classical.sign(payload, ec.ECDSA(hashes.SHA256()))
        )
        receipt["sig_v2"]["pqc"]["signature"] = _b64(self.pqc.sign(payload))
        return receipt

    def _build_challenge(self) -> dict[str, Any]:
        classical_key = self.classical.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        payload = copy.deepcopy(VALID_PAYMENT_REQUIRED)
        payload["extensions"]["pqc"] = {
            "version": 2,
            "algorithms": ["ECDSA-P256-SHA256", "ML-DSA-65"],
            "receipt": self.receipt,
            "verifyUrl": VERIFY_URL,
            "keys": {
                "TEST-ONLY-classical": _b64(classical_key),
                "TEST-ONLY-pqc": _b64(self.pqc.public_key().public_bytes_raw()),
            },
        }
        return payload

    def challenge(self) -> dict[str, Any]:
        return copy.deepcopy(self.capability)

    def transport(self) -> httpx.MockTransport:
        def handler(request: httpx.Request) -> httpx.Response:
            if str(request.url) == VERIFY_URL:
                receipt = json.loads(request.content)
                sig_v2 = receipt.get("sig_v2")
                if sig_v2 is None:
                    accepted = self.allow_downgrade or self.silent_downgrade
                    degraded = self.allow_downgrade
                else:
                    payload = _payload(receipt)
                    classical = base64.urlsafe_b64decode(sig_v2["classical"]["signature"] + "==")
                    pqc_sig = base64.urlsafe_b64decode(sig_v2["pqc"]["signature"] + "==")
                    try:
                        self.classical.public_key().verify(
                            classical, payload, ec.ECDSA(hashes.SHA256())
                        )
                        if not self.ignore_pqc:
                            self.pqc.public_key().verify(pqc_sig, payload)
                    except Exception:
                        accepted = False
                    else:
                        accepted = True
                    degraded = False
                return httpx.Response(200, json={"accepted": accepted, "degraded": degraded})
            return httpx.Response(
                402, headers={"PAYMENT-REQUIRED": encode_header(self.challenge())}, json={}
            )

        return httpx.MockTransport(handler)


assert TARGET_URL != VERIFY_URL
