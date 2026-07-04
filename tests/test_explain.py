"""Tests for the `explain` catalog helper (report.explain_check).

Offline: exercises the built-in check catalog with no network. Assertions use checks
that are present regardless of the optional [evm] extra (passive RS-HS-* and the
on-chain FA-SET-* supplement), so the test doesn't depend on the active registry loading.
"""

from __future__ import annotations

from x402_conformance.report import explain_check


def test_list_all_contains_core_checks() -> None:
    out = explain_check(None)
    assert "RS-HS-001" in out
    assert "FA-SET-003" in out  # on-chain supplement is included
    assert "check catalog" in out


def test_exact_id_shows_severity_spec_and_fix() -> None:
    out = explain_check("FA-SET-003")
    assert out.startswith("FA-SET-003 —")
    assert "critical" in out.lower()
    assert "CORE §10.1" in out
    # FA-SET-003 has a remediation hint
    assert "fix:" in out
    assert "double-settle" in out.lower()


def test_id_is_case_insensitive() -> None:
    assert explain_check("fa-set-003").startswith("FA-SET-003 —")


def test_prefix_lists_matches() -> None:
    out = explain_check("RS-HS")
    assert "match" in out
    assert "RS-HS-001" in out
    assert "RS-HS-002" in out


def test_unknown_id_is_reported_cleanly() -> None:
    out = explain_check("NOPE-999")
    assert "no check matches" in out
    # never raises, always a helpful string
    assert "explain" in out


def test_check_without_remediation_still_explains() -> None:
    # RS-PAY-003 has no remediation entry; explain must still show title/severity/spec.
    out = explain_check("RS-PAY-003")
    assert out.startswith("RS-PAY-003 —")
    assert "major" in out.lower()
    assert "fix:" not in out  # no hint for this one, and that's fine
