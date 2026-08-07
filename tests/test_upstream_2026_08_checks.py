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
