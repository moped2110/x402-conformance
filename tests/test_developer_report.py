"""Tests for the developer-facing remediation report (T-17)."""

from __future__ import annotations

from x402_conformance.checks import CheckResult, Severity, Status
from x402_conformance.report import to_developer_report


def _r(cid: str, severity: Severity, status: Status, detail: str = "") -> CheckResult:
    return CheckResult(cid, f"{cid} title", severity, "spec-v2.md §x", status, detail)


def test_failures_grouped_with_fix_and_spec() -> None:
    results = [
        _r("RS-NEG-003", Severity.CRITICAL, Status.FAIL, "served an invalid payment"),
        _r("RS-PR-009", Severity.MAJOR, Status.FAIL, "extra.name/version missing"),
        _r("RS-HS-001", Severity.MAJOR, Status.PASS),   # passes omitted
        _r("RS-PR-010", Severity.MINOR, Status.SKIP),   # skips omitted
    ]
    out = to_developer_report(results, "https://api.example/x")
    assert "NOT CONFORMANT" in out
    assert "CRITICAL" in out and "MAJOR" in out
    assert "RS-NEG-003" in out and "RS-PR-009" in out
    assert "RS-HS-001" not in out  # a passing check is not in the punch-list
    assert "what: served an invalid payment" in out
    assert "fix:" in out  # RS-NEG-003 carries a remediation hint
    assert "spec: spec-v2.md §x" in out


def test_conformant_when_no_failures() -> None:
    results = [
        _r("RS-HS-001", Severity.MAJOR, Status.PASS),
        _r("RS-PR-001", Severity.MAJOR, Status.SKIP),
    ]
    out = to_developer_report(results, "https://x")
    assert "no issues to fix" in out.lower()
    assert "✅" in out


def test_minor_only_is_advisory_not_blocking() -> None:
    results = [
        _r("RS-PR-010", Severity.MINOR, Status.FAIL, "too many tags"),
        _r("RS-HS-001", Severity.MAJOR, Status.PASS),
    ]
    out = to_developer_report(results, "https://x")
    assert "0 blocking" in out
    assert "advisory" in out.lower()
    assert "NOT CONFORMANT" not in out  # a MINOR failure alone does not block
