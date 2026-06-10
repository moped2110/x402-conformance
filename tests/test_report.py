"""Internal: report summary, CI exit-code gating, and JSON/Markdown shape."""

from __future__ import annotations

import json

from x402_conformance.checks import CheckResult, Severity, Status
from x402_conformance.report import exit_code, summarize, to_json, to_markdown


def _r(cid: str, status: Status, sev: Severity) -> CheckResult:
    return CheckResult(cid, f"title {cid}", sev, "spec", status, "")


def test_summarize_counts() -> None:
    results = [
        _r("A", Status.PASS, Severity.MAJOR),
        _r("B", Status.FAIL, Severity.MAJOR),
        _r("C", Status.SKIP, Severity.MINOR),
        _r("D", Status.ERROR, Severity.CRITICAL),
    ]
    s = summarize(results)
    assert s == {"total": 4, "passed": 1, "failed": 1, "skipped": 1, "errors": 1}


def test_minor_failure_does_not_gate() -> None:
    results = [_r("A", Status.PASS, Severity.MAJOR), _r("B", Status.FAIL, Severity.MINOR)]
    assert exit_code(results) == 0


def test_major_failure_gates() -> None:
    assert exit_code([_r("A", Status.FAIL, Severity.MAJOR)]) == 1


def test_critical_failure_gates() -> None:
    assert exit_code([_r("A", Status.FAIL, Severity.CRITICAL)]) == 1


def test_error_in_gating_severity_gates() -> None:
    # a crashing major/critical check must fail CI, not pass silently
    assert exit_code([_r("A", Status.ERROR, Severity.MAJOR)]) == 1


def test_all_pass_is_clean() -> None:
    assert exit_code([_r("A", Status.PASS, Severity.CRITICAL)]) == 0


def test_json_report_is_valid_and_complete() -> None:
    results = [_r("A", Status.PASS, Severity.MAJOR), _r("B", Status.FAIL, Severity.CRITICAL)]
    doc = json.loads(to_json(results, "https://t.example"))
    assert doc["target"] == "https://t.example"
    assert doc["conformant"] is False
    assert doc["summary"]["total"] == 2
    assert {r["check_id"] for r in doc["results"]} == {"A", "B"}
    assert "specBaseline" in doc and doc["tool"]["name"] == "x402-conformance"


def test_markdown_report_has_verdict_and_rows() -> None:
    md = to_markdown([_r("A", Status.PASS, Severity.MAJOR)], "https://t.example")
    assert "x402 Conformance Report" in md
    assert "CONFORMANT" in md
    assert "| A |" in md


def test_markdown_escapes_pipes_in_detail() -> None:
    r = CheckResult("X", "t", Severity.MINOR, "spec", Status.FAIL, "a | b | c")
    md = to_markdown([r], "u")
    # raw pipes would break the table; they must be escaped
    assert "a \\| b \\| c" in md
