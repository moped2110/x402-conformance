"""Internal: report summary, CI exit-code gating, and JSON/Markdown shape."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from x402_conformance.checks import CheckResult, Severity, Status
from x402_conformance.report import REPORT_VERSION, exit_code, summarize, to_json, to_markdown

_SCHEMA_PATH = Path(__file__).resolve().parents[1] / "report.schema.json"


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
    assert doc["reportVersion"] == REPORT_VERSION


def test_json_report_validates_against_published_schema() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    results = [
        _r("A", Status.PASS, Severity.MAJOR),
        _r("B", Status.FAIL, Severity.CRITICAL),
        CheckResult("C", "t", Severity.MINOR, "spec", Status.SKIP, "why"),
    ]
    doc = json.loads(to_json(results, "https://t.example"))
    jsonschema.validate(doc, schema)  # raises on any contract drift


def test_schema_validates_with_format_checked_timestamp() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    doc = json.loads(to_json([_r("A", Status.ERROR, Severity.CRITICAL)], "u"))
    # Enforce the declared `format: date-time` too, not just structure.
    jsonschema.validate(doc, schema, format_checker=jsonschema.FormatChecker())


def test_schema_rejects_unknown_severity() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    doc = json.loads(to_json([_r("A", Status.PASS, Severity.MAJOR)], "u"))
    doc["results"][0]["severity"] = "bogus"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(doc, schema)


def test_schema_rejects_unknown_status() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    doc = json.loads(to_json([_r("A", Status.PASS, Severity.MAJOR)], "u"))
    doc["results"][0]["status"] = "maybe"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(doc, schema)


def test_schema_rejects_additional_and_missing_fields() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    extra = json.loads(to_json([_r("A", Status.PASS, Severity.MAJOR)], "u"))
    extra["surprise"] = 1  # additionalProperties: false at the top level
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(extra, schema)
    missing = json.loads(to_json([_r("A", Status.PASS, Severity.MAJOR)], "u"))
    del missing["reportVersion"]  # a required field
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(missing, schema)


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


def test_markdown_neutralizes_html_in_detail() -> None:
    # a hostile endpoint echoes markup into an error reason
    r = CheckResult(
        "X", "t", Severity.MAJOR, "spec", Status.FAIL, "reason <img src=x onerror=alert(1)>"
    )
    md = to_markdown([r], "u")
    assert "<img" not in md
    assert "&lt;img src=x onerror=alert(1)&gt;" in md


def test_markdown_collapses_newlines_in_detail() -> None:
    # a newline in a cell would break the table row
    r = CheckResult("X", "t", Severity.MAJOR, "spec", Status.FAIL, "line1\nline2\r\nline3")
    md = to_markdown([r], "u")
    body = md.splitlines()
    row = next(line for line in body if line.startswith("| X "))
    assert "line1 line2 line3" in row
    assert "\n" not in row  # the row is a single line


def test_markdown_escapes_links_and_code_in_detail() -> None:
    r = CheckResult(
        "X", "t", Severity.MAJOR, "spec", Status.FAIL, "see [click](javascript:evil) and `code`"
    )
    md = to_markdown([r], "u")
    assert "[click]" not in md  # brackets escaped, link not formed
    assert "\\[click\\]" in md
    assert "\\`code\\`" in md


def test_markdown_sanitizes_backticks_in_target() -> None:
    # a backtick in the target would break out of the inline-code span
    md = to_markdown([_r("A", Status.PASS, Severity.MAJOR)], "http://x/`# pwn")
    assert "`# pwn" not in md
    assert "**Target:** `http://x/# pwn`" in md
