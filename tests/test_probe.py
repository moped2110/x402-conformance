"""Internal: the probe decodes the PAYMENT-REQUIRED header in clean stages.

Each failure layer (base64 -> JSON -> schema) must be reported distinctly so
checks can pinpoint where a response went wrong.
"""

from __future__ import annotations

import base64
import json

import httpx
from conftest import VALID_PAYMENT_REQUIRED, encode_header

from x402_conformance.probe import build_probe


def _probe_with(header: str | None, status: int = 402, extra: dict | None = None):
    headers = dict(extra or {})
    if header is not None:
        headers["PAYMENT-REQUIRED"] = header
    return build_probe(httpx.Response(status, headers=headers))


def test_clean_decode_of_valid_header() -> None:
    p = _probe_with(encode_header(VALID_PAYMENT_REQUIRED))
    assert p.decode_error is None
    assert p.json_error is None
    assert p.parse_error is None
    assert p.parsed is not None
    assert p.raw is not None


def test_invalid_base64_stops_at_decode() -> None:
    p = _probe_with("@@@not base64@@@")
    assert p.decode_error is not None
    assert p.raw is None and p.parsed is None


def test_valid_base64_invalid_json_stops_at_json() -> None:
    p = _probe_with(base64.b64encode(b"{broken").decode())
    assert p.decode_error is None
    assert p.json_error is not None
    assert p.parsed is None


def test_valid_json_schema_violation_stops_at_parse() -> None:
    broken = dict(VALID_PAYMENT_REQUIRED)
    del broken["accepts"]  # required field
    p = _probe_with(base64.b64encode(json.dumps(broken).encode()).decode())
    assert p.json_error is None
    assert p.raw is not None
    assert p.parse_error is not None
    assert "accepts" in p.parse_error


def test_top_level_json_array_is_rejected() -> None:
    p = _probe_with(base64.b64encode(b"[1,2,3]").decode())
    assert p.json_error is not None  # expected object, got array
    assert p.raw is None


def test_legacy_headers_detected() -> None:
    p = _probe_with(encode_header(VALID_PAYMENT_REQUIRED), extra={"X-PAYMENT": "legacy"})
    assert "x-payment" in p.legacy_headers_present


def test_header_absent() -> None:
    p = _probe_with(None)
    assert p.header_b64 is None
    assert p.parsed is None
