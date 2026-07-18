"""Tests for the batch facilitator scan aggregation (scan.py)."""

from __future__ import annotations

from x402_conformance.checks import CheckResult, Severity, Status
from x402_conformance.scan import (
    ScanEntry,
    format_scan,
    rank_scan,
    scan_to_dicts,
    summarize_scan,
)


def _r(cid: str, status: Status, severity: Severity = Severity.MAJOR) -> CheckResult:
    return CheckResult(cid, cid, severity, "ref", status, "")


def test_summarize_counts_and_gating() -> None:
    results = [
        _r("A", Status.PASS),
        _r("B", Status.FAIL, Severity.CRITICAL),  # gating
        _r("C", Status.FAIL, Severity.MINOR),  # non-gating fail
        _r("D", Status.SKIP),
        _r("E", Status.ERROR, Severity.MAJOR),  # gating
    ]
    e = summarize_scan("http://x", results)
    assert e.passed == 1 and e.failed == 2 and e.skipped == 1 and e.errors == 1
    assert e.gating_failures == 2  # B + E
    assert e.conformant is False
    assert set(e.fail_ids) == {"B", "C", "E"}


def test_minor_only_failure_is_conformant() -> None:
    e = summarize_scan("http://x", [_r("A", Status.PASS), _r("C", Status.FAIL, Severity.MINOR)])
    assert e.conformant is True
    assert e.gating_failures == 0
    assert e.failed == 1


def test_all_skipped_scan_is_inconclusive() -> None:
    e = summarize_scan("http://x", [_r("A", Status.SKIP)])
    assert e.conformant is False


def test_scan_redacts_url_components_and_errors() -> None:
    entry = ScanEntry(
        url="https://user:secret@example.test/private?token=secret",
        unreachable="failed at https://user:secret@example.test/private?token=secret",
    )
    [data] = scan_to_dicts([entry])
    rendered = str(data)
    assert data["url"] == "https://example.test"
    assert "secret" not in rendered
    assert "/private" not in rendered


def test_rank_orders_by_findings_then_unreachable_last() -> None:
    worst = ScanEntry(url="http://worst", gating_failures=3, failed=3, conformant=False)
    mid = ScanEntry(url="http://mid", gating_failures=1, failed=1, conformant=False)
    clean = ScanEntry(url="http://clean", gating_failures=0, failed=0, conformant=True)
    dead = ScanEntry(url="http://dead", unreachable="timeout")
    ranked = rank_scan([clean, dead, mid, worst])
    assert [e.url for e in ranked] == [
        "http://worst",
        "http://mid",
        "http://clean",
        "http://dead",
    ]


def test_format_marks_hits_and_unreachable() -> None:
    entries = [
        ScanEntry(
            url="http://bad", gating_failures=1, failed=1, conformant=False, fail_ids=["FA-VER-002"]
        ),
        ScanEntry(url="http://dead", unreachable="connect error"),
    ]
    out = format_scan(entries)
    assert "NOT CONFORMANT" in out
    assert "FA-VER-002" in out
    assert "unreachable" in out
    assert "1 non-conformant / 1 reachable" in out


def test_scan_to_dicts_is_ranked_and_serializable() -> None:
    entries = [
        ScanEntry(url="http://clean", conformant=True),
        ScanEntry(url="http://bad", gating_failures=2, conformant=False),
    ]
    dicts = scan_to_dicts(entries)
    assert dicts[0]["url"] == "http://bad"  # ranked first
    assert dicts[1]["url"] == "http://clean"
    assert set(dicts[0].keys()) >= {"url", "gating_failures", "conformant", "fail_ids"}
