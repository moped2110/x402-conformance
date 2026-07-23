"""FA-SUP-002: Algorand CAIP-2 is enforced — the dated deferral has been retired.

x402's reference facilitator once advertised Algorand networks as the untruncated
standard-base64 genesis hash, which CAIP-2 (Final) does not permit — reported as
x402-foundation/x402#2904. The check *deferred* that single form pending the maintainers'
answer. It has been answered: the fix shipped in x402#2931 (canonical URL-safe,
32-char-truncated ids, with legacy normalization on input). So the deferral is gone and a
non-CAIP-2 v2 network is a plain failure again. These tests pin that: the old shipped form
FAILs, the canonical form PASSes, and nothing is quietly excused.
"""

from __future__ import annotations

import httpx
import pytest

pytest.importorskip("eth_account")

from x402_conformance.checks import Status
from x402_conformance.checks.facilitator import run_facilitator_checks
from x402_conformance.report import assessment_exit_code

FAC = "http://facilitator.example"

ALGORAND_AS_SHIPPED = "algorand:SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI="
ALGORAND_CANONICAL = "algorand:SGO1GKSzyE7IEPItTxCByw9x8FmnrCDe"


def supported(*kinds: dict) -> httpx.MockTransport:
    """A MockTransport whose /supported returns the given kinds."""
    body = {"kinds": list(kinds), "extensions": [], "signers": {"eip155:*": []}}

    def handler(request: httpx.Request) -> httpx.Response:
        """Serve the supported body; 404 for anything else."""
        if request.url.path.endswith("/supported"):
            return httpx.Response(200, json=body)
        return httpx.Response(404, json={"detail": "Not Found"})

    return httpx.MockTransport(handler)


def kind(network: str, *, version: int = 2, scheme: str = "exact") -> dict:
    """Build one /supported kind entry."""
    entry: dict = {"x402Version": version, "network": network}
    if scheme:
        entry["scheme"] = scheme
    return entry


def sup002(transport: httpx.MockTransport):
    """Run the facilitator checks and return the FA-SUP-002 result."""
    results = run_facilitator_checks(FAC, transport=transport)
    return next(r for r in results if r.check_id == "FA-SUP-002")


def test_untruncated_algorand_form_now_fails() -> None:
    """The old untruncated base64 Algorand id is no longer deferred — it FAILs, untagged."""
    result = sup002(supported(kind("eip155:84532"), kind(ALGORAND_AS_SHIPPED)))
    assert result.status is Status.FAIL
    assert "not CAIP-2" in result.detail
    assert result.reason_code is None  # no deferral tag anymore


def test_a_failing_algorand_form_makes_the_run_fail_not_inconclusive() -> None:
    """A non-CAIP-2 v2 network now gates the run as a failure (exit 1), not a deferral (2)."""
    results = run_facilitator_checks(
        FAC, transport=supported(kind("eip155:84532"), kind(ALGORAND_AS_SHIPPED))
    )
    assert assessment_exit_code(results) == 1


def test_canonical_algorand_identifier_passes() -> None:
    """The CAIP-2 profile form (URL-safe, truncated to 32 chars) is well-formed and PASSes."""
    assert sup002(supported(kind(ALGORAND_CANONICAL))).status is Status.PASS


def test_a_clean_facilitator_is_conformant() -> None:
    """A facilitator advertising only valid CAIP-2 kinds is conformant (exit 0)."""
    results = run_facilitator_checks(FAC, transport=supported(kind("eip155:84532")))
    assert assessment_exit_code(results) == 0


def test_other_namespaces_still_fail_on_non_caip2() -> None:
    """A non-CAIP-2 id in any namespace fails — this was never Algorand-specific."""
    assert sup002(supported(kind("cosmos:this/is/not/caip2="))).status is Status.FAIL


def test_a_malformed_body_is_rejected_before_the_per_kind_loop() -> None:
    """A kind missing `scheme` fails /supported schema validation first: 'no valid kinds'."""
    result = sup002(supported({"x402Version": 2, "network": ALGORAND_AS_SHIPPED}))
    assert result.status is Status.SKIP
    assert "no valid" in result.detail
