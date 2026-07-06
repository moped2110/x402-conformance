"""A jp402 endpoint whose /openapi.json can't be fetched must leave a *reason* in
the session notes — not silently look like "no OpenAPI advertised". Guards the
diagnostic-transparency fix in runner._maybe_fetch_openapi.
"""

from __future__ import annotations

import base64
import json

import httpx

from x402_conformance.probe import PAYMENT_REQUIRED_HEADER, build_probe
from x402_conformance.runner import _maybe_fetch_openapi

_URL = "https://api.example.test/paid"
# A 402 that advertises the JP rail (x-jp402 on an accepts entry). The requirements
# ride in the PAYMENT-REQUIRED header (base64 JSON), which is where build_probe reads
# `raw` from — the body is not parsed.
_JP402_402 = {"x402Version": 2, "accepts": [{"scheme": "exact", "x-jp402": {"currency": "JPYC"}}]}
_PLAIN_402 = {"x402Version": 2, "accepts": [{"scheme": "exact"}]}


def _probe(payment_required: dict) -> object:
    b64 = base64.b64encode(json.dumps(payment_required).encode()).decode()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(402, headers={PAYMENT_REQUIRED_HEADER: b64})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        return build_probe(client.get(_URL))


def _client_openapi(status: int, *, body: object | None = None, raise_exc: bool = False):
    def handler(request: httpx.Request) -> httpx.Response:
        if raise_exc:
            raise httpx.ConnectError("refused")
        if body is not None:
            return httpx.Response(status, json=body)
        return httpx.Response(status, text="not json")

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_openapi_404_records_reason() -> None:
    first = _probe(_JP402_402)
    with _client_openapi(404, body={}) as client:
        doc, reason = _maybe_fetch_openapi(client, _URL, first)
    assert doc is None
    assert reason is not None and "404" in reason


def test_openapi_unreachable_records_reason() -> None:
    first = _probe(_JP402_402)
    with _client_openapi(200, raise_exc=True) as client:
        doc, reason = _maybe_fetch_openapi(client, _URL, first)
    assert doc is None
    assert reason is not None and "unreachable" in reason


def test_openapi_not_json_records_reason() -> None:
    first = _probe(_JP402_402)
    with _client_openapi(200) as client:  # body=None → non-JSON text
        doc, reason = _maybe_fetch_openapi(client, _URL, first)
    assert doc is None
    assert reason is not None and "not valid JSON" in reason


def test_openapi_success_returns_doc_no_reason() -> None:
    first = _probe(_JP402_402)
    with _client_openapi(200, body={"openapi": "3.0.0"}) as client:
        doc, reason = _maybe_fetch_openapi(client, _URL, first)
    assert doc == {"openapi": "3.0.0"}
    assert reason is None


def test_non_jp_endpoint_attempts_nothing_and_adds_no_note() -> None:
    first = _probe(_PLAIN_402)
    with _client_openapi(404, body={}) as client:
        doc, reason = _maybe_fetch_openapi(client, _URL, first)
    assert doc is None and reason is None
