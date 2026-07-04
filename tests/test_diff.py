"""Tests for the report diff (diff.diff_reports / format_diff)."""

from __future__ import annotations

import json

import pytest

from x402_conformance.diff import diff_reports, format_diff


def _report(target: str, statuses: dict[str, str]) -> str:
    return json.dumps(
        {
            "target": target,
            "timestamp": "2026-07-04T00:00:00+00:00",
            "results": [
                {"check_id": cid, "status": st} for cid, st in statuses.items()
            ],
        }
    )


def test_classifies_all_transitions() -> None:
    old = _report("http://x", {
        "RS-NEG-007": "fail",   # -> pass  (fixed)
        "FA-VER-002": "pass",   # -> fail  (regressed)
        "FA-ERR-001": "fail",   # -> fail  (still failing)
        "DI-002": "pass",       # removed in new
        "RS-HS-001": "pass",    # unchanged
    })
    new = _report("http://x", {
        "RS-NEG-007": "pass",
        "FA-VER-002": "fail",
        "FA-ERR-001": "fail",
        "RS-PR-016": "skip",    # added in new
        "RS-HS-001": "pass",
    })
    d = diff_reports(old, new)
    assert [t.check_id for t in d.fixed] == ["RS-NEG-007"]
    assert [t.check_id for t in d.regressed] == ["FA-VER-002"]
    assert [t.check_id for t in d.still_failing] == ["FA-ERR-001"]
    assert d.added == ["RS-PR-016"]
    assert d.removed == ["DI-002"]
    assert d.has_regressions is True


def test_identical_reports_are_unchanged() -> None:
    r = _report("http://x", {"RS-HS-001": "pass", "FA-ERR-001": "fail"})
    d = diff_reports(r, r)
    assert d.unchanged is True
    assert d.has_regressions is False
    assert "No changes" in format_diff(d)


def test_fix_only_has_no_regressions() -> None:
    old = _report("http://x", {"RS-NEG-007": "fail"})
    new = _report("http://x", {"RS-NEG-007": "pass"})
    d = diff_reports(old, new)
    assert d.has_regressions is False
    out = format_diff(d)
    assert "fixed" in out
    assert "no regressions" in out


def test_error_counts_as_failing_for_regression() -> None:
    old = _report("http://x", {"RS-SEC-011": "pass"})
    new = _report("http://x", {"RS-SEC-011": "error"})
    d = diff_reports(old, new)
    assert [t.check_id for t in d.regressed] == ["RS-SEC-011"]


def test_differing_targets_are_flagged() -> None:
    old = _report("http://a", {"RS-HS-001": "pass"})
    new = _report("http://b", {"RS-HS-001": "fail"})
    out = format_diff(diff_reports(old, new))
    assert "targets differ" in out


def test_invalid_json_raises_valueerror() -> None:
    with pytest.raises(ValueError):
        diff_reports("{not json", "{}")
