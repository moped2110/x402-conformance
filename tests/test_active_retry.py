"""Transient-fault retry in the active runner.

A conformance run may cross flaky infra (rate limiters, load balancers, cold
starts). Those faults are transient and not a verdict on the payment, so the
runner retries 429/502/503/504 and connection-level blips before giving up —
a real x402 client does the same. A *deterministic* fault reproduces on every
attempt and is still reported unchanged.
"""

from __future__ import annotations

import httpx
import pytest

pytest.importorskip("eth_account")

from conftest import VALID_PAYMENT_REQUIRED, encode_header

from x402_conformance import active
from x402_conformance.active import build_active_context
from x402_conformance.payload_builder import EvmSigner

TARGET = "https://api.example.com/premium-data"
SIGNER = EvmSigner.from_key("0x" + "33" * 32)


def _payment_required() -> httpx.Response:
    return httpx.Response(402, headers={"PAYMENT-REQUIRED": encode_header(VALID_PAYMENT_REQUIRED)})


def _context(handler, monkeypatch):
    # Kill the real backoff sleeps so tests stay instant; assert we were told to.
    slept: list[float] = []
    monkeypatch.setattr(active.time, "sleep", lambda s: slept.append(s))
    client = httpx.Client(transport=httpx.MockTransport(handler))
    ctx = build_active_context(client, TARGET, "GET", SIGNER)
    assert ctx is not None
    return ctx, slept


def test_transient_503_is_retried_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"pay": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if not request.headers.get("PAYMENT-SIGNATURE"):
            return _payment_required()  # probe
        calls["pay"] += 1
        if calls["pay"] <= 2:
            return httpx.Response(503)
        return httpx.Response(402)  # a clean rejection after the blip clears

    ctx, slept = _context(handler, monkeypatch)
    resp = ctx.send({"payload": {"authorization": {"from": SIGNER.address}}})

    assert calls["pay"] == 3  # two 503s + the successful 402
    assert resp.status_code == 402
    assert resp.transport_error is None
    assert len(slept) == 2  # backed off before each retry


def test_persistent_503_is_reported_after_retries(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"pay": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if not request.headers.get("PAYMENT-SIGNATURE"):
            return _payment_required()
        calls["pay"] += 1
        return httpx.Response(503)

    ctx, _ = _context(handler, monkeypatch)
    resp = ctx.send({"payload": {"authorization": {"from": SIGNER.address}}})

    assert calls["pay"] == 3  # exhausted all attempts
    assert resp.status_code == 503
    assert resp.endpoint_crashed  # a permanently-5xx endpoint stays a fault


def test_retry_after_header_is_honoured(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if not request.headers.get("PAYMENT-SIGNATURE"):
            return _payment_required()
        if request.headers.get("PAYMENT-SIGNATURE") and not getattr(handler, "hit", False):
            handler.hit = True  # type: ignore[attr-defined]
            return httpx.Response(429, headers={"Retry-After": "5"})
        return httpx.Response(402)

    ctx, slept = _context(handler, monkeypatch)
    resp = ctx.send({"payload": {"authorization": {"from": SIGNER.address}}})

    assert resp.status_code == 402
    assert slept == [5.0]  # waited exactly the server-requested delay


def test_hostile_retry_after_is_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if not request.headers.get("PAYMENT-SIGNATURE"):
            return _payment_required()
        if not getattr(handler, "hit", False):
            handler.hit = True  # type: ignore[attr-defined]
            return httpx.Response(503, headers={"Retry-After": "99999"})
        return httpx.Response(402)

    ctx, slept = _context(handler, monkeypatch)
    resp = ctx.send({"payload": {"authorization": {"from": SIGNER.address}}})

    assert resp.status_code == 402
    assert slept == [30.0]  # capped, not the 99999s the server asked for


def test_transient_connection_error_is_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"pay": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if not request.headers.get("PAYMENT-SIGNATURE"):
            return _payment_required()
        calls["pay"] += 1
        if calls["pay"] == 1:
            raise httpx.ConnectError("connection reset", request=request)
        return httpx.Response(402)

    ctx, slept = _context(handler, monkeypatch)
    resp = ctx.send({"payload": {"authorization": {"from": SIGNER.address}}})

    assert calls["pay"] == 2
    assert resp.status_code == 402
    assert resp.transport_error is None
    assert len(slept) == 1


def test_nonretryable_protocol_error_is_reported_immediately(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = {"pay": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if not request.headers.get("PAYMENT-SIGNATURE"):
            return _payment_required()
        calls["pay"] += 1
        raise httpx.RemoteProtocolError("peer closed connection", request=request)

    ctx, slept = _context(handler, monkeypatch)
    resp = ctx.send({"payload": {"authorization": {"from": SIGNER.address}}})

    assert calls["pay"] == 1  # not retried — the endpoint broke, that's a finding
    assert resp.transport_error == "RemoteProtocolError"
    assert resp.endpoint_crashed
    assert slept == []
