"""XRPL rides the chain-agnostic passive checks (K2-2).

The passive resource checks — handshake, PaymentRequired shape, CAIP-2 network — are
chain-agnostic: they accept any valid CAIP-2 namespace. An XRPL 402 must therefore
pass them, while the EVM-specific checks skip rather than fail. There is a normative
XRPL `exact` scheme upstream (t54 facilitator / x402-foundation specs/schemes); deep
XRPL-specific field validation (asset/issuer, invoiceId/MemoData binding) is a
follow-up. What we can gate safely today is the one unambiguous mismatch: an EVM
`0x` address on an XRPL rail (XRPL uses classic r-addresses), mirroring RS-PR-013's
Solana branch.
"""

from __future__ import annotations

import copy

import httpx
from conftest import TARGET_URL, VALID_PAYMENT_REQUIRED, encode_header

from x402_conformance.checks import Severity, Status
from x402_conformance.runner import run_checks

# A well-formed XRPL classic r-address and a plausible issuer account.
_XRPL_PAYTO = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe"
_XRPL_ASSET = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"


def by_id(results: list, check_id: str):
    return next(r for r in results if r.check_id == check_id)


def _xrpl_402(*, network: str = "xrpl:0", pay_to: str = _XRPL_PAYTO) -> httpx.MockTransport:
    payload = copy.deepcopy(VALID_PAYMENT_REQUIRED)
    payload["accepts"] = [
        {
            "scheme": "exact",
            "network": network,
            "amount": "10000",
            "asset": _XRPL_ASSET,
            "payTo": pay_to,
            "maxTimeoutSeconds": 60,
        }
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(402, headers={"PAYMENT-REQUIRED": encode_header(payload)}, json={})

    return httpx.MockTransport(handler)


def test_xrpl_network_is_accepted_as_caip2() -> None:
    results = run_checks(TARGET_URL, transport=_xrpl_402())
    assert by_id(results, "RS-PR-006").status is Status.PASS


def test_both_xrpl_networks_pass() -> None:
    for network in ("xrpl:0", "xrpl:1"):
        results = run_checks(TARGET_URL, transport=_xrpl_402(network=network))
        assert by_id(results, "RS-PR-006").status is Status.PASS


def test_evm_specific_checks_skip_rather_than_fail() -> None:
    results = run_checks(TARGET_URL, transport=_xrpl_402())
    for check_id in ("RS-PR-008", "RS-PR-009"):
        assert by_id(results, check_id).status is Status.SKIP


def test_a_wellformed_xrpl_402_has_no_gating_failure() -> None:
    # The breadth claim: an XRPL 402 must clear the chain-agnostic gating checks.
    results = run_checks(TARGET_URL, transport=_xrpl_402())
    gating = [
        r
        for r in results
        if r.status is Status.FAIL and r.severity in (Severity.CRITICAL, Severity.MAJOR)
    ]
    assert not gating, [f"{r.check_id}: {r.detail}" for r in gating]


def test_an_evm_address_on_an_xrpl_rail_is_a_mismatch() -> None:
    # The one XRPL-specific thing we can gate without a per-chain validator: a 0x EVM
    # address on an XRPL network cannot be right.
    results = run_checks(
        TARGET_URL,
        transport=_xrpl_402(pay_to="0x209693Bc6afc0C5328bA36FaF03C514EF312287C"),
    )
    mismatch = by_id(results, "RS-PR-013")
    assert mismatch.status is Status.FAIL
    assert "xrpl" in mismatch.detail
