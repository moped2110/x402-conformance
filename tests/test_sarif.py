"""SARIF 2.1.0 export: findings-only, correct levels, valid envelope.

SARIF is the machine-readable format GitHub code scanning and bug-bounty platforms
ingest, so its shape is a contract. These tests pin the invariants a consumer relies
on: version/schema, findings-only results, severity→level mapping, deduped rules.
"""

from __future__ import annotations

import json

from x402_conformance.checks import CheckResult, Severity, Status
from x402_conformance.report import to_sarif

_TARGET = "https://api.example.test/paid"


def _result(check_id: str, severity: Severity, status: Status) -> CheckResult:
    return CheckResult(
        check_id=check_id,
        title=f"{check_id} title",
        severity=severity,
        spec_ref="x402-specification-v2.md",
        status=status,
        detail="something went wrong",
    )


def _sample() -> list[CheckResult]:
    return [
        _result("RS-HS-001", Severity.MAJOR, Status.FAIL),
        _result("RS-SEC-003", Severity.MINOR, Status.FAIL),
        _result("RS-PR-001", Severity.MAJOR, Status.PASS),  # not a finding
        _result("FA-VER-002", Severity.MAJOR, Status.SKIP),  # not a finding
        _result("RS-NEG-003", Severity.CRITICAL, Status.ERROR),
    ]


def test_envelope_is_valid_sarif_210() -> None:
    doc = json.loads(to_sarif(_sample(), _TARGET))
    assert doc["version"] == "2.1.0"
    assert "sarif-schema-2.1.0" in doc["$schema"]
    assert len(doc["runs"]) == 1
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "x402-conformance"
    assert driver["version"]  # non-empty


def test_only_failures_and_errors_become_results() -> None:
    doc = json.loads(to_sarif(_sample(), _TARGET))
    ids = [r["ruleId"] for r in doc["runs"][0]["results"]]
    # FAIL + ERROR only; PASS and SKIP are excluded.
    assert set(ids) == {"RS-HS-001", "RS-SEC-003", "RS-NEG-003"}


def test_severity_maps_to_sarif_level() -> None:
    doc = json.loads(to_sarif(_sample(), _TARGET))
    level = {r["ruleId"]: r["level"] for r in doc["runs"][0]["results"]}
    assert level["RS-HS-001"] == "error"  # major → error
    assert level["RS-NEG-003"] == "error"  # critical → error
    assert level["RS-SEC-003"] == "warning"  # minor → warning


def test_rules_are_deduped_and_cover_findings() -> None:
    # A finding id appearing twice must yield exactly one rule.
    results = [
        _result("RS-HS-001", Severity.MAJOR, Status.FAIL),
        _result("RS-HS-001", Severity.MAJOR, Status.ERROR),
    ]
    doc = json.loads(to_sarif(results, _TARGET))
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == ["RS-HS-001"]


def test_results_carry_location_and_fingerprint() -> None:
    doc = json.loads(to_sarif(_sample(), _TARGET))
    r = doc["runs"][0]["results"][0]
    uri = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "https://api.example.test"
    assert "sha256:" in r["partialFingerprints"]["x402ConformanceCheckId"]


def test_clean_run_has_no_results_and_is_marked_conformant() -> None:
    doc = json.loads(to_sarif([_result("RS-HS-001", Severity.MAJOR, Status.PASS)], _TARGET))
    run = doc["runs"][0]
    assert run["results"] == []
    assert run["properties"]["conformant"] is True
