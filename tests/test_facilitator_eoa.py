"""FA-VER-003: a facilitator must reject an asset that is an EOA (x402#2554).

A facilitator that skips an ``eth_getCode`` pre-flight would accept a payment
whose ``asset`` points at a wallet address; the on-chain simulation does not
revert, so settlement is a silent no-op. /verify must report ``isValid:false``.
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("eth_account")

import httpx

from x402_conformance.checks import Status
from x402_conformance.checks.facilitator import (
    _EOA_ASSET,
    FacilitatorContext,
    evaluate_facilitator,
)
from x402_conformance.payload_builder import EvmSigner

REQ = {
    "scheme": "exact", "network": "eip155:84532", "amount": "10000",
    "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
    "maxTimeoutSeconds": 300, "extra": {"name": "USDC", "version": "2"},
}
SIGNER = EvmSigner.from_key("0x" + "33" * 32)


def _by_id(results, cid):  # type: ignore[no-untyped-def]
    return next(r for r in results if r.check_id == cid)


def _ctx(handler) -> FacilitatorContext:  # type: ignore[no-untyped-def]
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return FacilitatorContext(base_url="http://fac.test", client=client,
                              requirements=REQ, signer=SIGNER)


def test_fa_ver_003_passes_when_eoa_asset_rejected() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/verify"):
            body = json.loads(request.content)
            asset = body["paymentRequirements"]["asset"]
            if asset.lower() == _EOA_ASSET.lower():
                return httpx.Response(200, json={
                    "isValid": False, "invalidReason": "asset_not_deployed_contract"})
            return httpx.Response(200, json={"isValid": True})
        return httpx.Response(404)

    r = _by_id(evaluate_facilitator(_ctx(handler)), "FA-VER-003")
    assert r.status == Status.PASS, r.detail
    assert "correctly rejected" in r.detail


def test_fa_ver_003_fails_when_eoa_asset_accepted() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        # A vulnerable facilitator: accepts everything, no eth_getCode pre-flight.
        return httpx.Response(200, json={"isValid": True})

    r = _by_id(evaluate_facilitator(_ctx(handler)), "FA-VER-003")
    assert r.status == Status.FAIL
    assert "EOA" in r.detail


# --- FA-SUP-001: /supported is OPTIONAL (CORE §7.3) — absent must not fail ---

def _supported_ctx(status: int, json_body: object | None = None) -> FacilitatorContext:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/supported"):
            return httpx.Response(status) if json_body is None else httpx.Response(status, json=json_body)
        return httpx.Response(404)

    return _ctx(handler)


def test_fa_sup_001_skips_when_supported_absent() -> None:
    # A conforming facilitator may omit /supported (404) — requirements come inline
    # in the 402. Must be SKIP, not FAIL (was a false positive vs non-CDP facilitators).
    r = _by_id(evaluate_facilitator(_supported_ctx(404)), "FA-SUP-001")
    assert r.status == Status.SKIP, r.detail
    assert "optional" in r.detail.lower()


def test_fa_sup_001_fails_when_present_but_malformed() -> None:
    # Present (200) but missing keys is a real fault — still caught.
    r = _by_id(evaluate_facilitator(_supported_ctx(200, {"kinds": []})), "FA-SUP-001")
    assert r.status == Status.FAIL


def test_fa_sup_001_passes_on_good_supported() -> None:
    good = {"kinds": [], "extensions": [], "signers": {}}
    r = _by_id(evaluate_facilitator(_supported_ctx(200, good)), "FA-SUP-001")
    assert r.status == Status.PASS
