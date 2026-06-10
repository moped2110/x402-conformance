"""Tests for the FA facilitator checks against correct and buggy mock facilitators."""

from __future__ import annotations

import json

import httpx
import pytest

pytest.importorskip("eth_account")

from x402_conformance.checks import Status
from x402_conformance.checks.facilitator import run_facilitator_checks
from x402_conformance.payload_builder import EvmSigner

from conftest import VALID_PAYMENT_REQUIRED, encode_header

FAC = "http://facilitator.example"
RES = "http://resource.example/data"
REQ = VALID_PAYMENT_REQUIRED["accepts"][0]
SIGNER = EvmSigner.from_key("0x" + "33" * 32)

GOOD_SUPPORTED = {
    "kinds": [{"x402Version": 2, "scheme": "exact", "network": "eip155:84532"}],
    "extensions": [],
    "signers": {"eip155:*": ["0x0000000000000000000000000000000000000001"]},
}


def make_facilitator(
    *, supported: dict | None = None, verify_buggy: bool = False,
) -> httpx.MockTransport:
    body = GOOD_SUPPORTED if supported is None else supported

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "GET" and path == "/data":
            return httpx.Response(402, headers={"PAYMENT-REQUIRED": encode_header(VALID_PAYMENT_REQUIRED)})
        if request.method == "GET" and path == "/supported":
            return httpx.Response(200, json=body)
        if request.method == "POST" and path == "/verify":
            payload = json.loads(request.content)
            auth = payload["paymentPayload"]["payload"]["authorization"]
            req = payload["paymentRequirements"]
            valid = int(auth["value"]) == int(req["amount"])
            if verify_buggy:
                return httpx.Response(200, json={"isValid": True, "payer": auth["from"]})
            if valid:
                return httpx.Response(200, json={"isValid": True, "payer": auth["from"]})
            return httpx.Response(200, json={
                "isValid": False,
                "invalidReason": "invalid_exact_evm_payload_authorization_value_mismatch",
                "payer": auth["from"],
            })
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def by_id(results, cid):
    return next(r for r in results if r.check_id == cid)


def test_correct_facilitator_supported_and_verify() -> None:
    results = run_facilitator_checks(
        FAC, resource_url=RES, signer=SIGNER, transport=make_facilitator()
    )
    assert by_id(results, "FA-SUP-001").status == Status.PASS
    assert by_id(results, "FA-SUP-002").status == Status.PASS
    assert by_id(results, "FA-VER-002").status == Status.PASS
    assert by_id(results, "FA-ERR-001").status == Status.PASS


def test_supported_missing_signers_fails() -> None:
    bad = {"kinds": GOOD_SUPPORTED["kinds"], "extensions": []}  # no signers
    results = run_facilitator_checks(FAC, transport=make_facilitator(supported=bad))
    assert by_id(results, "FA-SUP-001").status == Status.FAIL


def test_kind_non_caip2_fails() -> None:
    bad = {"kinds": [{"x402Version": 2, "scheme": "exact", "network": "base-sepolia"}],
           "extensions": [], "signers": {}}
    results = run_facilitator_checks(FAC, transport=make_facilitator(supported=bad))
    assert by_id(results, "FA-SUP-002").status == Status.FAIL


def test_buggy_verify_accepts_underpayment_is_caught() -> None:
    results = run_facilitator_checks(
        FAC, resource_url=RES, signer=SIGNER, transport=make_facilitator(verify_buggy=True)
    )
    assert by_id(results, "FA-VER-002").status == Status.FAIL


def test_no_resource_skips_verify_checks() -> None:
    results = run_facilitator_checks(FAC, transport=make_facilitator())
    assert by_id(results, "FA-VER-002").status == Status.SKIP
    assert by_id(results, "FA-ERR-001").status == Status.SKIP
    # SUP checks still run
    assert by_id(results, "FA-SUP-001").status == Status.PASS
