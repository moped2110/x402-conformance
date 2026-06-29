"""Tests for the RS-NEG active checks against correct and deliberately-buggy mocks.

Calibration principle: against a correctly-validating endpoint every active
check must PASS (zero false positives). Against an endpoint missing a specific
validation, the corresponding check must FAIL (it catches the bug).
"""

from __future__ import annotations

import base64
import json
import time

import httpx
import pytest

pytest.importorskip("eth_account")

from eth_account import Account
from eth_account.messages import encode_typed_data

from x402_conformance.active import run_active_checks
from x402_conformance.checks import Status
from x402_conformance.payload_builder import EvmSigner, _TRANSFER_WITH_AUTHORIZATION_TYPES

from conftest import VALID_PAYMENT_REQUIRED, encode_header

TARGET = "https://api.example.com/premium-data"
REQ = VALID_PAYMENT_REQUIRED["accepts"][0]
CHAIN_ID = 84532


def _recovers_to_from(payload: dict) -> bool:
    # Wrap the whole thing: a mangled `from`/`value`/`nonce` (e.g. RS-SEC-007's
    # control chars) is not encodable as an address/uint, so encode_typed_data
    # raises. A correct server treats that as "signature does not recover" and
    # rejects cleanly — it must not let the exception escape.
    auth = payload["payload"]["authorization"]
    try:
        domain = {"name": REQ["extra"]["name"], "version": REQ["extra"]["version"],
                  "chainId": CHAIN_ID, "verifyingContract": REQ["asset"]}
        message = {"from": auth["from"], "to": auth["to"], "value": int(auth["value"]),
                   "validAfter": int(auth["validAfter"]), "validBefore": int(auth["validBefore"]),
                   "nonce": bytes.fromhex(auth["nonce"].removeprefix("0x"))}
        signable = encode_typed_data(domain, _TRANSFER_WITH_AUTHORIZATION_TYPES, message)
        recovered = Account.recover_message(signable, signature=payload["payload"]["signature"])
    except Exception:
        return False
    return recovered == auth["from"]


def make_server(
    *, check_signature: bool = True, check_amount: bool = True,
    check_recipient: bool = True, check_time: bool = True,
    check_version: bool = True, check_accepts: bool = True,
) -> httpx.MockTransport:
    """A configurable x402 resource server. Defaults = fully correct."""

    def reject(reason: str) -> httpx.Response:
        body = {"success": False, "errorReason": reason, "transaction": "",
                "network": REQ["network"]}
        return httpx.Response(402, headers={"PAYMENT-RESPONSE": encode_header(body)})

    def handler(request: httpx.Request) -> httpx.Response:
        sig = request.headers.get("PAYMENT-SIGNATURE")
        if sig is None:
            return httpx.Response(402, headers={"PAYMENT-REQUIRED": encode_header(VALID_PAYMENT_REQUIRED)})
        try:
            decoded = base64.b64decode(sig, validate=True)
        except Exception:
            return httpx.Response(400)
        try:
            payload = json.loads(decoded)
            auth = payload["payload"]["authorization"]
        except Exception:
            return httpx.Response(400)

        if check_version and payload.get("x402Version") != 2:
            return reject("invalid_x402_version")
        if check_accepts:
            acc = payload.get("accepted") or {}
            if acc.get("scheme") != "exact" or acc.get("network") != REQ["network"]:
                return reject("invalid_network")
        if check_recipient and auth.get("to") != REQ["payTo"]:
            return reject("invalid_exact_evm_payload_recipient_mismatch")
        if check_amount and str(auth.get("value")) != str(REQ["amount"]):
            return reject("invalid_exact_evm_payload_authorization_value_mismatch")
        now = int(time.time())
        if check_time and not (int(auth["validAfter"]) <= now <= int(auth["validBefore"])):
            return reject("invalid_exact_evm_payload_authorization_validity")
        if check_signature and not _recovers_to_from(payload):
            return reject("invalid_exact_evm_payload_signature")

        # Valid payment — serve the resource (negative checks never reach here).
        ok = {"success": True, "transaction": "0x" + "ab" * 32, "network": REQ["network"],
              "payer": auth["from"]}
        return httpx.Response(200, headers={"PAYMENT-RESPONSE": encode_header(ok)},
                              json={"data": "premium"})

    return httpx.MockTransport(handler)


SIGNER = EvmSigner.from_key("0x" + "22" * 32)


def by_id(results, cid):
    return next(r for r in results if r.check_id == cid)


def test_correct_server_passes_all_active_checks() -> None:
    results = run_active_checks(TARGET, SIGNER, transport=make_server())
    bad = [(r.check_id, r.status.value, r.detail) for r in results
           if r.status not in (Status.PASS, Status.SKIP)]
    assert bad == [], bad
    # sanity: we actually ran the group, not skipped everything
    assert any(r.status == Status.PASS for r in results)


def test_server_without_signature_check_is_caught() -> None:
    results = run_active_checks(TARGET, SIGNER, transport=make_server(check_signature=False))
    # the tampered-signature case must catch it
    assert by_id(results, "RS-NEG-003").status == Status.FAIL


def test_amount_bug_caught_specifically_by_neg_013() -> None:
    # Server verifies signatures but forgets to validate the price against its own.
    results = run_active_checks(
        TARGET, SIGNER, transport=make_server(check_amount=False)
    )
    # 013 pays a valid-signed token amount and claims it is the price → must be caught
    assert by_id(results, "RS-NEG-013").status == Status.FAIL
    # post-signing underpayment (005) is still caught by the signature check, so it stays PASS
    assert by_id(results, "RS-NEG-005").status == Status.PASS


def test_recipient_bug_caught() -> None:
    results = run_active_checks(
        TARGET, SIGNER, transport=make_server(check_signature=False, check_recipient=False)
    )
    assert by_id(results, "RS-NEG-007").status == Status.FAIL


def test_sec_011_extreme_amount_handled_cleanly_passes() -> None:
    # Correct server rejects the 2²⁵⁶-1 amount (value mismatch) with a clean 402.
    results = run_active_checks(TARGET, SIGNER, transport=make_server())
    assert by_id(results, "RS-SEC-011").status == Status.PASS


def test_sec_011_extreme_amount_crash_is_caught() -> None:
    # A naive backend that 5xx-crashes on a huge value must be flagged.
    def handler(request: httpx.Request) -> httpx.Response:
        sig = request.headers.get("PAYMENT-SIGNATURE")
        if sig is None:
            return httpx.Response(402, headers={"PAYMENT-REQUIRED": encode_header(VALID_PAYMENT_REQUIRED)})
        value = int(json.loads(base64.b64decode(sig))["payload"]["authorization"]["value"])
        if value > 10**30:
            return httpx.Response(500)
        return httpx.Response(402)

    results = run_active_checks(TARGET, SIGNER, transport=httpx.MockTransport(handler))
    assert by_id(results, "RS-SEC-011").status == Status.FAIL


def test_sec_011_marker_leak_on_extreme_amount_is_caught() -> None:
    marker = "PREMIUM_LEAK_ON_HUGE"

    def handler(request: httpx.Request) -> httpx.Response:
        sig = request.headers.get("PAYMENT-SIGNATURE")
        if sig is None:
            return httpx.Response(402, headers={"PAYMENT-REQUIRED": encode_header(VALID_PAYMENT_REQUIRED)})
        # Rejects cleanly (402, no 5xx) but leaks the resource in the body.
        return httpx.Response(402, text=f"too much: {marker}")

    results = run_active_checks(
        TARGET, SIGNER, transport=httpx.MockTransport(handler), resource_marker=marker
    )
    r = by_id(results, "RS-SEC-011")
    assert r.status == Status.FAIL and "leaked" in r.detail, r.detail


def test_resource_marker_leak_on_rejection_is_caught() -> None:
    marker = "TOP_SECRET_CAVIAR_RECIPE"

    def handler(request: httpx.Request) -> httpx.Response:
        sig = request.headers.get("PAYMENT-SIGNATURE")
        if sig is None:
            return httpx.Response(402, headers={"PAYMENT-REQUIRED": encode_header(VALID_PAYMENT_REQUIRED)})
        # Rejects with 402 but leaks the protected content in the error body.
        return httpx.Response(402, text=f"payment failed, but here it is: {marker}")

    results = run_active_checks(
        TARGET, SIGNER, transport=httpx.MockTransport(handler), resource_marker=marker
    )
    leaked = [r for r in results if r.status == Status.FAIL and "leaked" in r.detail]
    assert leaked, "marker leak on the rejection path was not caught"


def test_resource_marker_absent_no_false_positive() -> None:
    # Correct server never echoes the marker → passing the flag must not add failures.
    results = run_active_checks(
        TARGET, SIGNER, transport=make_server(), resource_marker="NEVER_APPEARS_XYZ"
    )
    assert not [r for r in results if r.status == Status.FAIL]


def test_no_eip3009_requirement_skips_all() -> None:
    # An endpoint advertising only a non-eip3009 scheme → nothing to attack.
    solana_only = {
        "x402Version": 2,
        "resource": {"url": TARGET},
        "accepts": [{"scheme": "exact", "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
                     "amount": "10000", "asset": "So11111111111111111111111111111111111111112",
                     "payTo": "CKPKJWNdJEqa81x7CkZ14BVPiY6y16Sxs7owznqtWYp5",
                     "maxTimeoutSeconds": 60}],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(402, headers={"PAYMENT-REQUIRED": encode_header(solana_only)})

    results = run_active_checks(TARGET, SIGNER, transport=httpx.MockTransport(handler))
    assert all(r.status == Status.SKIP for r in results)


def test_neg_015_eoa_asset_silent_bypass_is_caught() -> None:
    # A facilitator that trusts the client's asset and skips an eth_getCode
    # pre-flight: it recovers the signature against the *claimed* (EOA) asset and
    # serves — the silent-no-op bypass class (x402#2554). RS-NEG-015 must catch it.
    def handler(request: httpx.Request) -> httpx.Response:
        sig = request.headers.get("PAYMENT-SIGNATURE")
        if sig is None:
            return httpx.Response(402, headers={"PAYMENT-REQUIRED": encode_header(VALID_PAYMENT_REQUIRED)})
        payload = json.loads(base64.b64decode(sig))
        auth = payload["payload"]["authorization"]
        asset = payload["accepted"]["asset"]  # trust the client's asset (the bug)
        domain = {"name": REQ["extra"]["name"], "version": REQ["extra"]["version"],
                  "chainId": CHAIN_ID, "verifyingContract": asset}
        message = {"from": auth["from"], "to": auth["to"], "value": int(auth["value"]),
                   "validAfter": int(auth["validAfter"]), "validBefore": int(auth["validBefore"]),
                   "nonce": bytes.fromhex(auth["nonce"].removeprefix("0x"))}
        signable = encode_typed_data(domain, _TRANSFER_WITH_AUTHORIZATION_TYPES, message)
        try:
            recovered = Account.recover_message(signable, signature=payload["payload"]["signature"])
        except Exception:
            return httpx.Response(402)
        if recovered != auth["from"]:
            return httpx.Response(402)
        # No eth_getCode check → serves even though the asset is an EOA.
        ok = {"success": True, "transaction": "0x" + "ab" * 32, "network": REQ["network"],
              "payer": auth["from"]}
        return httpx.Response(200, headers={"PAYMENT-RESPONSE": encode_header(ok)},
                              json={"data": "premium"})

    results = run_active_checks(TARGET, SIGNER, transport=httpx.MockTransport(handler))
    assert by_id(results, "RS-NEG-015").status == Status.FAIL


def test_sec_005_oversized_header_crash_is_caught() -> None:
    # A backend that 5xx-crashes on a very large PAYMENT-SIGNATURE header must be flagged.
    def handler(request: httpx.Request) -> httpx.Response:
        sig = request.headers.get("PAYMENT-SIGNATURE")
        if sig is None:
            return httpx.Response(402, headers={"PAYMENT-REQUIRED": encode_header(VALID_PAYMENT_REQUIRED)})
        if len(sig) > 100_000:
            return httpx.Response(500)  # chokes on the oversized header
        return httpx.Response(402)

    results = run_active_checks(TARGET, SIGNER, transport=httpx.MockTransport(handler))
    assert by_id(results, "RS-SEC-005").status == Status.FAIL


def test_sec_007_control_chars_crash_is_caught() -> None:
    # A naive parser that 5xx-crashes on control characters in a field must be flagged.
    def handler(request: httpx.Request) -> httpx.Response:
        sig = request.headers.get("PAYMENT-SIGNATURE")
        if sig is None:
            return httpx.Response(402, headers={"PAYMENT-REQUIRED": encode_header(VALID_PAYMENT_REQUIRED)})
        try:
            frm = json.loads(base64.b64decode(sig))["payload"]["authorization"]["from"]
        except Exception:
            return httpx.Response(400)
        if "\x00" in frm:
            return httpx.Response(500)  # crashes on the embedded NUL
        return httpx.Response(402)

    results = run_active_checks(TARGET, SIGNER, transport=httpx.MockTransport(handler))
    assert by_id(results, "RS-SEC-007").status == Status.FAIL


def test_neg_011_unoffered_accept_served_is_caught() -> None:
    # A server that ignores the claimed `accepted` (wrong network) and serves anyway.
    results = run_active_checks(TARGET, SIGNER, transport=make_server(check_accepts=False))
    assert by_id(results, "RS-NEG-011").status == Status.FAIL


def test_neg_012_wrong_version_served_is_caught() -> None:
    # A server that ignores a bogus top-level x402Version and serves anyway.
    results = run_active_checks(TARGET, SIGNER, transport=make_server(check_version=False))
    assert by_id(results, "RS-NEG-012").status == Status.FAIL
