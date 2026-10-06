"""RS-NEG-016: the resource server owns builder-code `a` validation.

builder_code.md (x402#3302/#3313/#3320): before forwarding a v2 payment, the
resource server MUST reject it with `extension_echo_mismatch` when the echoed
`a` differs from the declared `info.a`. The facilitator-side check was removed,
so a server that skips it lets any client re-attribute the payment.
"""

from __future__ import annotations

import base64
import copy
import json
from typing import Any

import httpx
import pytest

pytest.importorskip("eth_account")

from conftest import VALID_PAYMENT_REQUIRED, encode_header

from x402_conformance.active import run_active_checks
from x402_conformance.checks import Status
from x402_conformance.checks.negative import _mismatched_builder_code_echo
from x402_conformance.payload_builder import EvmSigner

TARGET = "https://api.example.com/premium-data"
SIGNER = EvmSigner.from_key("0x" + "77" * 32)

DECLARED: dict[str, Any] = copy.deepcopy(VALID_PAYMENT_REQUIRED)
DECLARED["extensions"] = {"builder-code": {"info": {"a": "my_app", "s": ["srv"]}}}


def _server(mode: str, challenge: dict[str, Any] = DECLARED) -> httpx.MockTransport:
    """``mode``: 'correct' | 'forwards' | 'silent' | 'serves'."""

    def handler(request: httpx.Request) -> httpx.Response:
        sig = request.headers.get("PAYMENT-SIGNATURE")
        if sig is None:
            return httpx.Response(402, headers={"PAYMENT-REQUIRED": encode_header(challenge)})
        payload = json.loads(base64.b64decode(sig))
        echo = (payload.get("extensions") or {}).get("builder-code") or {}
        info = echo.get("info", echo)
        declared = challenge.get("extensions", {}).get("builder-code", {}).get("info", {})
        mismatch = "a" in info and info["a"] != declared.get("a")
        if not mismatch:
            # Otherwise-valid probes from the rest of the active group are rejected
            # for their own tampering; keep them out of this file's concern.
            return httpx.Response(402, headers={"PAYMENT-REQUIRED": encode_header(challenge)})
        if mode == "correct":
            body = {**challenge, "error": "extension_echo_mismatch"}
            return httpx.Response(402, headers={"PAYMENT-REQUIRED": encode_header(body)})
        if mode == "forwards":
            # The facilitator rejects the unfunded payer.
            body = {**challenge, "error": "insufficient_funds"}
            return httpx.Response(402, headers={"PAYMENT-REQUIRED": encode_header(body)})
        if mode == "silent":
            return httpx.Response(402)
        return httpx.Response(200, json={"data": "premium"})

    return httpx.MockTransport(handler)


def _neg_016(transport: httpx.MockTransport) -> Any:
    results = run_active_checks(TARGET, SIGNER, transport=transport)
    return next(r for r in results if r.check_id == "RS-NEG-016")


def test_server_rejecting_the_mismatch_passes() -> None:
    result = _neg_016(_server("correct"))
    assert result.status is Status.PASS
    assert "extension_echo_mismatch" in result.detail
    assert result.severity.value == "major"


def test_server_forwarding_the_mismatch_fails() -> None:
    result = _neg_016(_server("forwards"))
    assert result.status is Status.FAIL
    assert "insufficient_funds" in result.detail


def test_server_serving_the_mismatch_fails() -> None:
    assert _neg_016(_server("serves")).status is Status.FAIL


def test_rejection_without_a_reason_passes_with_a_note() -> None:
    result = _neg_016(_server("silent"))
    assert result.status is Status.PASS
    assert "not visible" in result.detail


def test_skips_without_a_builder_code_declaration() -> None:
    result = _neg_016(_server("correct", challenge=VALID_PAYMENT_REQUIRED))
    assert result.status is Status.SKIP


def test_echo_keeps_the_declared_shape() -> None:
    flat = {"builder-code": {"a": "my_app"}, "other": {"x": 1}}
    tampered, probe = _mismatched_builder_code_echo(flat) or ({}, "")
    assert tampered["builder-code"]["a"] == probe != "my_app"
    assert tampered["other"] == {"x": 1}
    assert flat["builder-code"]["a"] == "my_app"  # the context is not mutated
    nested, _ = _mismatched_builder_code_echo(DECLARED["extensions"]) or ({}, "")
    assert nested["builder-code"]["info"]["s"] == ["srv"]
    assert nested["builder-code"]["info"]["a"] != "my_app"
    # no `a` declared: the probe still sets one, which the server MUST reject too
    bare, _ = _mismatched_builder_code_echo({"builder-code": {"info": {}}}) or ({}, "")
    assert bare["builder-code"]["info"]["a"]
