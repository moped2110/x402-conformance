"""Checks added from the 2026-08 upstream review (61349de..c7e0ac8).

* DI-004   — external ``$ref``/``$id`` in a catalogued Bazaar schema (x402#3039)
* RS-PR-023/024 — builder-code app code and server service-code reservation
                  (x402#3027, #2994)
* RS-HS-008 — the *paid* 200 must not be shared-cacheable (x402#2990)
"""

from __future__ import annotations

import copy
from typing import Any

import httpx
import pytest
from conftest import TARGET_URL, encode_header

from x402_conformance.checks.base import Status
from x402_conformance.checks.discovery import external_schema_references
from x402_conformance.runner import run_checks

# --------------------------------------------------------------------------
# DI-004 — external schema references
# --------------------------------------------------------------------------


def test_same_document_fragments_are_clean() -> None:
    schema = {
        "$id": "#root",
        "type": "object",
        "properties": {"a": {"$ref": "#/definitions/a"}},
        "definitions": {"a": {"type": "string"}},
    }
    assert external_schema_references(schema) == []


@pytest.mark.parametrize(
    "ref",
    [
        "https://evil.example/schema.json",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
        "./sibling.json",
        "../up.json",
    ],
)
def test_external_references_are_found(ref: str) -> None:
    """http(s), file and relative forms all make the resolver fetch something."""
    hits = external_schema_references({"properties": {"a": {"$ref": ref}}})
    assert len(hits) == 1
    assert ref in hits[0]


def test_external_id_is_found_too() -> None:
    """`$id` re-bases resolution, so a remote `$id` is the same exposure as `$ref`."""
    hits = external_schema_references({"$id": "https://evil.example/base/"})
    assert len(hits) == 1


def test_nested_and_listed_references_are_found() -> None:
    schema = {
        "allOf": [
            {"type": "object"},
            {"items": {"deep": {"$ref": "https://evil.example/a.json"}}},
        ]
    }
    hits = external_schema_references(schema)
    assert len(hits) == 1
    assert "allOf[1]" in hits[0]


def test_non_string_reference_is_a_finding() -> None:
    """A non-string `$ref` is not a safe fragment either — fail closed."""
    assert external_schema_references({"$ref": {"nested": "trick"}})


# --------------------------------------------------------------------------
# RS-PR-023 / RS-PR-024 — builder-code
# --------------------------------------------------------------------------


def _challenge_with_builder_code(payload: dict[str, Any], info: Any) -> dict[str, Any]:
    out = copy.deepcopy(payload)
    out["extensions"] = {"builder-code": {"info": info, "schema": {"type": "object"}}}
    return out


def _run(payload: dict[str, Any]) -> dict[str, Any]:
    header = encode_header(payload)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(402, headers={"PAYMENT-REQUIRED": header}, json={})

    results = run_checks(TARGET_URL, transport=httpx.MockTransport(handler))
    return {r.check_id: r for r in results}


def test_builder_code_absent_skips(valid_payload: dict[str, Any]) -> None:
    by_id = _run(valid_payload)
    assert by_id["RS-PR-023"].status is Status.SKIP
    assert by_id["RS-PR-024"].status is Status.SKIP


def test_valid_builder_code_passes(valid_payload: dict[str, Any]) -> None:
    by_id = _run(_challenge_with_builder_code(valid_payload, {"a": "my_app", "s": ["sdk_one"]}))
    assert by_id["RS-PR-023"].status is Status.PASS
    assert by_id["RS-PR-024"].status is Status.PASS


@pytest.mark.parametrize("bad", ["My_App", "app-name", "", "x" * 33, 42])
def test_malformed_app_code_fails(valid_payload: dict[str, Any], bad: Any) -> None:
    by_id = _run(_challenge_with_builder_code(valid_payload, {"a": bad}))
    assert by_id["RS-PR-023"].status is Status.FAIL


def test_scalar_service_code_is_accepted(valid_payload: dict[str, Any]) -> None:
    """The spec allows a bare string on either side; it merges as a 1-element array."""
    by_id = _run(_challenge_with_builder_code(valid_payload, {"a": "my_app", "s": "just_one"}))
    assert by_id["RS-PR-024"].status is Status.PASS


def test_server_over_its_reservation_fails(valid_payload: dict[str, Any]) -> None:
    """MAX_SERVER_SERVICE_CODES is 5; a sixth is truncated downstream, so the
    attribution declared here is not the attribution that settles."""
    codes = [f"svc_{i}" for i in range(6)]
    by_id = _run(_challenge_with_builder_code(valid_payload, {"a": "my_app", "s": codes}))
    assert by_id["RS-PR-024"].status is Status.FAIL
    assert "reservation" in by_id["RS-PR-024"].detail


def test_exactly_at_the_reservation_passes(valid_payload: dict[str, Any]) -> None:
    codes = [f"svc_{i}" for i in range(5)]
    by_id = _run(_challenge_with_builder_code(valid_payload, {"a": "my_app", "s": codes}))
    assert by_id["RS-PR-024"].status is Status.PASS


def test_malformed_service_code_fails(valid_payload: dict[str, Any]) -> None:
    by_id = _run(_challenge_with_builder_code(valid_payload, {"a": "my_app", "s": ["Bad-Code"]}))
    assert by_id["RS-PR-024"].status is Status.FAIL


def test_service_codes_wrong_type_fails(valid_payload: dict[str, Any]) -> None:
    by_id = _run(_challenge_with_builder_code(valid_payload, {"a": "my_app", "s": {"k": "v"}}))
    assert by_id["RS-PR-024"].status is Status.FAIL


def test_builder_code_without_app_code_is_not_a_failure(valid_payload: dict[str, Any]) -> None:
    """`a` is optional; a server may declare only its own service codes."""
    by_id = _run(_challenge_with_builder_code(valid_payload, {"s": ["sdk_one"]}))
    assert by_id["RS-PR-023"].status is Status.PASS
    assert by_id["RS-PR-024"].status is Status.PASS


# ==========================================================================
# Second upstream window: c7e0ac8..f62a9fac
# ==========================================================================
#
#   * CORE §6.1 payment flow models made `assetTransferMethod` and `paymentFlow`
#     protocol-reserved, and named `auth-capture` as a fourth scheme. Both turned
#     previously-correct checks into wrong verdicts.
#   * RS-PR-025/026 grade the new flow field.


def _entry(**over: Any) -> dict[str, Any]:
    base = {
        "scheme": "exact",
        "network": "eip155:84532",
        "amount": "10000",
        "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
        "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
        "maxTimeoutSeconds": 60,
        "extra": {"name": "USDC", "version": "2"},
    }
    base.update(over)
    return base


def _run_accepts(payload: dict[str, Any], accepts: list[dict[str, Any]]) -> dict[str, Any]:
    out = copy.deepcopy(payload)
    out["accepts"] = accepts
    return _run(out)


# --- the wrong verdicts CORE §6.1 created ---------------------------------


def test_upto_may_carry_assetTransferMethod(valid_payload: dict[str, Any]) -> None:
    """The regression this window's fix is about.

    §6.1 makes `assetTransferMethod` protocol-reserved and names `upto` when
    explaining why — "distinguishing an SVM upto `escrow` default from an EVM upto
    `authorization` default". RS-PR-019 used to FAIL exactly this.
    """
    entry = _entry(scheme="upto", extra={"assetTransferMethod": "permit2"})
    assert _run_accepts(valid_payload, [entry])["RS-PR-019"].status is Status.PASS


def test_exact_may_carry_paymentFlow(valid_payload: dict[str, Any]) -> None:
    """The other reserved key, on the other scheme."""
    entry = _entry(extra={"name": "USDC", "version": "2", "paymentFlow": "authorization"})
    assert _run_accepts(valid_payload, [entry])["RS-PR-019"].status is Status.PASS


def test_genuine_scheme_extra_mismatch_still_fails(valid_payload: dict[str, Any]) -> None:
    """Relaxing the reserved keys must not blunt the check itself."""
    entry = _entry(extra={"withdrawDelay": 600, "receiverAuthorizer": "0xabc"})
    assert _run_accepts(valid_payload, [entry])["RS-PR-019"].status is Status.FAIL


def test_upto_carrying_exact_only_keys_fails(valid_payload: dict[str, Any]) -> None:
    """The upto branch now grades the real exact vocabulary, not one reserved key."""
    entry = _entry(scheme="upto", extra={"name": "USDC", "version": "2"})
    assert _run_accepts(valid_payload, [entry])["RS-PR-019"].status is Status.FAIL


def test_auth_capture_is_a_payable_scheme(valid_payload: dict[str, Any]) -> None:
    """`auth-capture` has a spec directory and a wire identifier; CORE §6 now names
    it alongside the other three. RS-PR-017 used to call it unpayable."""
    entry = _entry(scheme="auth-capture", extra={"autoCapture": False, "paymentFlow": "escrow"})
    assert _run_accepts(valid_payload, [entry])["RS-PR-017"].status is Status.PASS


def test_invented_scheme_still_fails(valid_payload: dict[str, Any]) -> None:
    assert _run_accepts(valid_payload, [_entry(scheme="totally-made-up")])["RS-PR-017"].status is (
        Status.FAIL
    )


# --- RS-PR-025 / RS-PR-026 -------------------------------------------------


def test_no_payment_flow_declared_skips(valid_payload: dict[str, Any]) -> None:
    by_id = _run_accepts(valid_payload, [_entry()])
    assert by_id["RS-PR-025"].status is Status.SKIP
    assert by_id["RS-PR-026"].status is Status.SKIP


@pytest.mark.parametrize("flow", ["authorization", "upfront", "escrow"])
def test_defined_flows_pass(valid_payload: dict[str, Any], flow: str) -> None:
    entry = _entry(extra={"name": "USDC", "version": "2", "paymentFlow": flow})
    assert _run_accepts(valid_payload, [entry])["RS-PR-025"].status is Status.PASS


@pytest.mark.parametrize("flow", ["Authorization", "deferred", "", 3, None])
def test_undefined_flow_fails(valid_payload: dict[str, Any], flow: Any) -> None:
    """An invented value makes the entry unpayable: §6.1 says a client MUST NOT
    construct a payment for a flow it does not recognize."""
    entry = _entry(extra={"name": "USDC", "version": "2", "paymentFlow": flow})
    result = _run_accepts(valid_payload, [entry])["RS-PR-025"]
    assert result.status is Status.FAIL
    assert result.severity.value == "major"


def test_escrow_entry_declaring_its_flow_passes_cleanly(valid_payload: dict[str, Any]) -> None:
    entry = _entry(
        scheme="upto",
        extra={"withdrawDelay": 600, "receiverAuthorizer": "0xabc", "paymentFlow": "escrow"},
    )
    result = _run_accepts(valid_payload, [entry])["RS-PR-026"]
    assert result.status is Status.PASS
    assert "advisory" not in result.detail


def test_escrow_entry_without_a_flow_is_advisory_not_a_failure(
    valid_payload: dict[str, Any],
) -> None:
    """Upstream contradicts itself here: CORE §6.1 says paymentFlow MUST be present
    for a non-authorization flow, scheme_upto_svm.md says omit it to default to
    `escrow`. Failing an endpoint for picking one half of that is not a verdict we
    are entitled to, so it reports and never gates."""
    entry = _entry(scheme="upto", extra={"withdrawDelay": 600, "receiverAuthorizer": "0xabc"})
    result = _run_accepts(valid_payload, [entry])["RS-PR-026"]
    assert result.status is Status.PASS
    assert "advisory" in result.detail
    assert result.severity.value == "minor"
