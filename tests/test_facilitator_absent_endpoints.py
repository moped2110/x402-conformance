"""A missing endpoint is not a verdict.

Pointing the `facilitator` subcommand at something that is not a facilitator — a
resource server, a bare host — used to produce *both* kinds of wrong answer at once:
FA-VER-002/003 and FA-ERR-001 reported FAIL because `/verify` "did not answer
properly", while FA-VER-004 reported **PASS** because a 404 is technically a clean
4xx. The second is the dangerous one: it manufactures evidence of conformance out of
an endpoint that does not exist.

Observed in the field on 2026-07-18 against a real resource server (`1 passed,
3 failed`), which is why these tests exist. Absence must SKIP — never FAIL (we would
accuse a correct service) and never PASS (we would certify untested behaviour).
"""

from __future__ import annotations

import httpx
import pytest

pytest.importorskip("eth_account")

from conftest import VALID_PAYMENT_REQUIRED, encode_header

from x402_conformance import safety
from x402_conformance.checks import Status
from x402_conformance.checks.facilitator import run_facilitator_checks
from x402_conformance.payload_builder import EvmSigner

FAC = "http://not-a-facilitator.example"
RES = "http://not-a-facilitator.example/paywall/demo/data"
SIGNER = EvmSigner.from_key("0x" + "44" * 32)

#: The checks that interrogate /verify. None of them may grade a missing endpoint.
VERIFY_CHECKS = ("FA-VER-002", "FA-VER-003", "FA-VER-004", "FA-ERR-001")
SETTLE_CHECKS = ("FA-SET-001", "FA-SET-002", "FA-SET-003")


@pytest.fixture(autouse=True)
def _safe_rpc_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(safety, "read_rpc_chain_id", lambda _url: 84532)


def resource_server_only(*, absent_status: int = 404) -> httpx.MockTransport:
    """A correct x402 resource server: it serves a paywall and has no facilitator API."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path.endswith("/data"):
            return httpx.Response(
                402, headers={"PAYMENT-REQUIRED": encode_header(VALID_PAYMENT_REQUIRED)}
            )
        # Everything a facilitator would expose simply is not there.
        return httpx.Response(absent_status, json={"detail": "Not Found"})

    return httpx.MockTransport(handler)


def by_id(results: list, check_id: str):
    return next(r for r in results if r.check_id == check_id)


@pytest.mark.parametrize("absent_status", [404, 405, 501])
@pytest.mark.parametrize("check_id", VERIFY_CHECKS)
def test_missing_verify_endpoint_skips_instead_of_grading(
    check_id: str, absent_status: int
) -> None:
    results = run_facilitator_checks(
        FAC,
        resource_url=RES,
        signer=SIGNER,
        transport=resource_server_only(absent_status=absent_status),
    )
    result = by_id(results, check_id)
    assert result.status is Status.SKIP, (
        f"{check_id} returned {result.status} for a missing /verify: {result.detail}"
    )
    assert "not implemented" in result.detail
    # K1-6: the skip is tagged so the run-level verdict can report endpoint_absent.
    assert result.reason_code == "endpoint_absent"


def test_clean_4xx_check_does_not_pass_on_a_missing_endpoint() -> None:
    # The specific regression: FA-VER-004 scored a 404 as "clean HTTP 404 on invalid
    # input". A customer could point the tool at nothing and collect a green check.
    results = run_facilitator_checks(
        FAC, resource_url=RES, signer=SIGNER, transport=resource_server_only()
    )
    assert by_id(results, "FA-VER-004").status is not Status.PASS


def test_no_check_fails_against_a_correct_resource_server() -> None:
    # A resource server is not a broken facilitator. Nothing here may gate.
    results = run_facilitator_checks(
        FAC, resource_url=RES, signer=SIGNER, transport=resource_server_only()
    )
    failed = [r.check_id for r in results if r.status is Status.FAIL]
    assert not failed, f"missing facilitator endpoints were graded as failures: {failed}"


def test_missing_settle_endpoint_skips_the_whole_group() -> None:
    results = run_facilitator_checks(
        FAC,
        resource_url=RES,
        signer=SIGNER,
        allow_settle=True,
        rpc_url="http://rpc.local",
        transport=resource_server_only(),
    )
    for check_id in SETTLE_CHECKS:
        result = by_id(results, check_id)
        assert result.status is Status.SKIP
        assert result.reason_code == "endpoint_absent"


def test_a_present_but_broken_verify_still_fails() -> None:
    # The counter-test: absence skips, but a real endpoint answering wrongly must
    # still gate. Otherwise this fix would have traded false alarms for blindness.
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path.endswith("/data"):
            return httpx.Response(
                402, headers={"PAYMENT-REQUIRED": encode_header(VALID_PAYMENT_REQUIRED)}
            )
        if request.url.path.endswith("/verify"):
            # Exists, and wrongly accepts an underpaying payment.
            return httpx.Response(200, json={"isValid": True, "payer": "0x" + "55" * 20})
        return httpx.Response(404, json={"detail": "Not Found"})

    results = run_facilitator_checks(
        FAC, resource_url=RES, signer=SIGNER, transport=httpx.MockTransport(handler)
    )
    assert by_id(results, "FA-VER-002").status is Status.FAIL
