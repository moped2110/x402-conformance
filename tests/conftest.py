"""Shared fixtures: a mock x402 resource server built on httpx.MockTransport.

The valid PaymentRequired payload is taken verbatim from the spec example
(x402-specification-v2.md §5.1.1) so our reference for "correct" is the spec
itself, not our own assumptions.
"""

from __future__ import annotations

import base64
import copy
import json
from typing import Any

import httpx
import pytest

from x402_conformance.run_record import NO_LOG_ENV

TARGET_URL = "https://api.example.com/premium-data"


@pytest.fixture(autouse=True)
def _suppress_default_run_log(monkeypatch: pytest.MonkeyPatch) -> None:
    """Run logging is on by default and would litter ./x402-runs during CLI tests.
    Suppress the *default* dir here; a test that passes an explicit --log-dir still
    writes to its own tmp path."""
    monkeypatch.setenv(NO_LOG_ENV, "1")


# Spec example, x402-specification-v2.md §5.1.1
VALID_PAYMENT_REQUIRED: dict[str, Any] = {
    "x402Version": 2,
    "error": "PAYMENT-SIGNATURE header is required",
    "resource": {
        "url": "https://api.example.com/premium-data",
        "description": "Access to premium market data",
        "mimeType": "application/json",
        "serviceName": "Example Market Data",
        "tags": ["market-data", "finance"],
        "iconUrl": "https://api.example.com/icon.png",
    },
    "accepts": [
        {
            "scheme": "exact",
            "network": "eip155:84532",
            "amount": "10000",
            "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
            "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
            "maxTimeoutSeconds": 60,
            "extra": {"name": "USDC", "version": "2"},
        }
    ],
    "extensions": {},
}


def encode_header(payload: dict[str, Any]) -> str:
    return base64.b64encode(json.dumps(payload).encode()).decode()


def transport_with_402(
    payload: dict[str, Any] | None = None,
    *,
    header_value: str | None = None,
    status_code: int = 402,
    extra_headers: dict[str, str] | None = None,
) -> httpx.MockTransport:
    """Mock server answering every request like an x402 resource server."""
    if header_value is None and payload is not None:
        header_value = encode_header(payload)

    def handler(request: httpx.Request) -> httpx.Response:
        headers = dict(extra_headers or {})
        if header_value is not None:
            headers["PAYMENT-REQUIRED"] = header_value
        return httpx.Response(status_code, headers=headers, json={})

    return httpx.MockTransport(handler)


@pytest.fixture
def valid_payload() -> dict[str, Any]:
    return copy.deepcopy(VALID_PAYMENT_REQUIRED)


@pytest.fixture
def valid_transport(valid_payload: dict[str, Any]) -> httpx.MockTransport:
    return transport_with_402(valid_payload)
