"""Batch facilitator scan — run the FA checks over many URLs and rank by findings.

Recon aid: point it at a list of facilitator base URLs and it returns a ranked table —
the facilitators with the most gating (critical/major) failures first, i.e. the ones whose
`/verify` waves through what it should reject. Passive only: no `/settle`, no funds move; the
scan just observes and ranks. Disclosure discipline (check each target's policy, report
privately) is on the operator, not automated here.

The aggregation (`summarize_scan` / `rank_scan` / `format_scan`) is pure and unit-tested;
the CLI wires it to the live `run_facilitator_checks` runner.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .checks import CheckResult, Severity, Status
from .report import exit_code, summarize

_GATING = (Severity.CRITICAL, Severity.MAJOR)
_BAD = (Status.FAIL, Status.ERROR)


@dataclass
class ScanEntry:
    """One facilitator's scan outcome."""

    url: str
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    errors: int = 0
    gating_failures: int = 0
    conformant: bool = True
    unreachable: str | None = None
    fail_ids: list[str] = field(default_factory=list)


def summarize_scan(url: str, results: list[CheckResult]) -> ScanEntry:
    """Fold a facilitator's check results into a ScanEntry."""
    s = summarize(results)
    gating = [r for r in results if r.status in _BAD and r.severity in _GATING]
    return ScanEntry(
        url=url,
        passed=s["passed"],
        failed=s["failed"],
        skipped=s["skipped"],
        errors=s["errors"],
        gating_failures=len(gating),
        conformant=exit_code(results) == 0,
        fail_ids=[r.check_id for r in results if r.status in _BAD],
    )


def rank_scan(entries: list[ScanEntry]) -> list[ScanEntry]:
    """Most interesting first: reachable before unreachable, then most gating failures,
    then most total failures, then URL for stability."""
    return sorted(
        entries,
        key=lambda e: (
            e.unreachable is not None,
            -e.gating_failures,
            -(e.failed + e.errors),
            e.url,
        ),
    )


def format_scan(entries: list[ScanEntry]) -> str:
    ranked = rank_scan(entries)
    lines = [f"facilitator scan — {len(ranked)} target(s), ranked by findings", ""]
    for e in ranked:
        if e.unreachable is not None:
            lines.append(f"  ?  {e.url}  — unreachable ({e.unreachable})")
            continue
        verdict = "CONFORMANT" if e.conformant else "NOT CONFORMANT"
        flag = "  " if e.conformant else "!!"
        lines.append(
            f"  {flag} {e.url}  — {verdict}: {e.gating_failures} gating, "
            f"{e.failed} failed, {e.errors} err, {e.passed} passed, {e.skipped} skipped"
        )
        if e.fail_ids:
            lines.append(f"        failing: {', '.join(e.fail_ids)}")
    reachable = [e for e in ranked if e.unreachable is None]
    hits = [e for e in reachable if not e.conformant]
    lines.append("")
    lines.append(
        f"Summary: {len(hits)} non-conformant / {len(reachable)} reachable "
        f"({len(ranked) - len(reachable)} unreachable)."
    )
    return "\n".join(lines) + "\n"


def scan_to_dicts(entries: list[ScanEntry]) -> list[dict[str, object]]:
    """Ranked entries as plain dicts (for JSON output)."""
    return [asdict(e) for e in rank_scan(entries)]
