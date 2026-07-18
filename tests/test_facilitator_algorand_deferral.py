"""FA-SUP-002: the Algorand CAIP-2 divergence is deferred, not excused.

x402's reference facilitator advertises Algorand networks as the untruncated
standard-base64 genesis hash, which CAIP-2 (Final) does not permit. Reported as
x402-foundation/x402#2904. Until that is answered the check reports SKIP rather than
FAIL — we do not gate on a point whose applicability is under clarification.

The risk of such an exception is that it quietly grows into a category of excuse. These
tests pin its edges: only the algorand namespace, only the identifier encoding, and only
when nothing else is wrong with the kind.
"""

from __future__ import annotations

import httpx
import pytest

pytest.importorskip("eth_account")

from x402_conformance.checks import Status
from x402_conformance.checks.base import DEFERRED_PENDING_UPSTREAM
from x402_conformance.checks.facilitator import run_facilitator_checks
from x402_conformance.report import assessment_exit_code

FAC = "http://facilitator.example"

ALGORAND_AS_SHIPPED = "algorand:SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI="
ALGORAND_CANONICAL = "algorand:SGO1GKSzyE7IEPItTxCByw9x8FmnrCDe"


def supported(*kinds: dict) -> httpx.MockTransport:
    body = {"kinds": list(kinds), "extensions": [], "signers": {"eip155:*": []}}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/supported"):
            return httpx.Response(200, json=body)
        return httpx.Response(404, json={"detail": "Not Found"})

    return httpx.MockTransport(handler)


def kind(network: str, *, version: int = 2, scheme: str = "exact") -> dict:
    entry: dict = {"x402Version": version, "network": network}
    if scheme:
        entry["scheme"] = scheme
    return entry


def sup002(transport: httpx.MockTransport):
    results = run_facilitator_checks(FAC, transport=transport)
    return next(r for r in results if r.check_id == "FA-SUP-002")


def test_algorand_encoding_is_deferred_with_the_issue_reference() -> None:
    result = sup002(supported(kind("eip155:84532"), kind(ALGORAND_AS_SHIPPED)))
    assert result.status is Status.SKIP
    # The reader must be able to see what was not judged, and why.
    assert "#2904" in result.detail
    assert "not CAIP-2" in result.detail


def test_a_deferral_carries_a_machine_readable_reason_code() -> None:
    # The verdict logic must not have to read prose to know a point was not judged.
    result = sup002(supported(kind("eip155:84532"), kind(ALGORAND_AS_SHIPPED)))
    assert result.reason_code == DEFERRED_PENDING_UPSTREAM


def test_a_deferral_prevents_a_conformant_verdict() -> None:
    # The regression this exists for: against x402.org the run reported
    # "CONFORMANT — 1 passed, 0 failed, 8 skipped" with exit 0, because the only
    # gating finding had been deferred. Certifying conformance while stating that a
    # gating point was not judged asserts more than was checked.
    results = run_facilitator_checks(
        FAC, transport=supported(kind("eip155:84532"), kind(ALGORAND_AS_SHIPPED))
    )
    assert assessment_exit_code(results) == 2


def test_without_a_deferral_a_clean_facilitator_is_still_conformant() -> None:
    # Counter-test: the new rule must not make every facilitator inconclusive.
    results = run_facilitator_checks(FAC, transport=supported(kind("eip155:84532")))
    assert assessment_exit_code(results) == 0


def test_canonical_algorand_identifier_passes() -> None:
    # Once upstream adopts the profile form, this is what a conformant answer looks
    # like — and it must pass without touching the deferral path.
    assert sup002(supported(kind(ALGORAND_CANONICAL))).status is Status.PASS


def test_other_namespaces_still_fail_on_non_caip2() -> None:
    # The exception is for `algorand:` only. A different namespace with the same
    # defect must still gate.
    result = sup002(supported(kind("cosmos:this/is/not/caip2=")))
    assert result.status is Status.FAIL


def test_a_malformed_body_is_rejected_before_the_deferral_can_apply() -> None:
    # A kind missing `scheme` never reaches FA-SUP-002's per-kind loop: /supported is
    # schema-validated first (see _get_supported), so the check reports "no valid
    # kinds" rather than a deferral. Pinned because it means the deferral cannot be
    # reached by sending a malformed response — the only way in is a well-formed body
    # whose sole defect is the Algorand identifier encoding.
    result = sup002(supported({"x402Version": 2, "network": ALGORAND_AS_SHIPPED}))
    assert result.status is Status.SKIP
    assert "no valid" in result.detail
    assert "#2904" not in result.detail


def test_a_real_failure_elsewhere_outranks_the_deferral() -> None:
    # Mixed input: one deferred Algorand encoding plus one genuine problem. The run
    # must report FAIL, not SKIP — otherwise the deferral would mask the defect.
    result = sup002(supported(kind(ALGORAND_AS_SHIPPED), kind("eip155:1", version=3)))
    assert result.status is Status.FAIL
    assert "x402Version" in result.detail
