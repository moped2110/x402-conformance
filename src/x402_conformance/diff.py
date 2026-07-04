"""Diff two JSON conformance reports — "did my fix work?".

Compares an *old* and a *new* report (as produced by ``report.to_json``) check-by-check
and classifies every transition: fixed (a failure that now passes), regressed (a pass that
now fails), still-failing, added, and removed checks. The CLI ``diff`` command gates its exit
code on regressions, so this doubles as a CI guard: a change that breaks a previously-passing
check fails the build.

Only the ``results`` array (``check_id`` + ``status``) is required; everything else in the
report shape is optional, so the diff stays tolerant across ``reportVersion`` bumps.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

_PASS = "pass"
_BAD = ("fail", "error")


def _index(report: dict[str, Any]) -> dict[str, str]:
    """Map ``check_id -> status`` from a report's ``results`` array."""
    out: dict[str, str] = {}
    for r in report.get("results", []):
        cid = r.get("check_id")
        if isinstance(cid, str):
            out[cid] = str(r.get("status", ""))
    return out


@dataclass(frozen=True)
class Transition:
    """One check's status change between the two reports."""

    check_id: str
    old: str
    new: str


@dataclass
class DiffResult:
    """Classified differences between two reports."""

    old_target: str = ""
    new_target: str = ""
    old_time: str = ""
    new_time: str = ""
    fixed: list[Transition] = field(default_factory=list)         # bad -> pass
    regressed: list[Transition] = field(default_factory=list)     # pass -> bad
    still_failing: list[Transition] = field(default_factory=list)  # bad -> bad
    other_changes: list[Transition] = field(default_factory=list)  # any other status change
    added: list[str] = field(default_factory=list)                # only in new
    removed: list[str] = field(default_factory=list)              # only in old

    @property
    def has_regressions(self) -> bool:
        return bool(self.regressed)

    @property
    def unchanged(self) -> bool:
        return not (
            self.fixed or self.regressed or self.other_changes
            or self.added or self.removed
        )


def diff_reports(old_json: str, new_json: str) -> DiffResult:
    """Diff two report JSON strings. Raises ``ValueError`` on unparseable input."""
    try:
        old = json.loads(old_json)
        new = json.loads(new_json)
    except json.JSONDecodeError as exc:
        raise ValueError(f"report is not valid JSON: {exc}") from exc
    if not isinstance(old, dict) or not isinstance(new, dict):
        raise ValueError("each report must be a JSON object")

    old_idx, new_idx = _index(old), _index(new)
    res = DiffResult(
        old_target=str(old.get("target", "")),
        new_target=str(new.get("target", "")),
        old_time=str(old.get("timestamp", "")),
        new_time=str(new.get("timestamp", "")),
    )
    for cid in sorted(old_idx.keys() | new_idx.keys()):
        o, n = old_idx.get(cid), new_idx.get(cid)
        if o is None:
            res.added.append(cid)
        elif n is None:
            res.removed.append(cid)
        elif o in _BAD and n in _BAD:
            # failing in both reports (same or changed bad status) — context, not a "change"
            res.still_failing.append(Transition(cid, o, n))
        elif o == n:
            continue  # unchanged pass/skip
        elif o in _BAD and n == _PASS:
            res.fixed.append(Transition(cid, o, n))
        elif o == _PASS and n in _BAD:
            res.regressed.append(Transition(cid, o, n))
        else:
            res.other_changes.append(Transition(cid, o, n))
    return res


def format_diff(d: DiffResult) -> str:
    """Render a DiffResult as a human-readable report."""
    lines = ["x402 conformance — diff (old → new)"]
    if d.old_target or d.new_target:
        lines.append(f"  old: {d.old_target or '?'}  {d.old_time}")
        lines.append(f"  new: {d.new_target or '?'}  {d.new_time}")
    if d.old_target and d.new_target and d.old_target != d.new_target:
        lines.append("  ⚠ targets differ — comparing different endpoints")
    lines.append("")

    if d.unchanged:
        lines.append("No changes — every check has the same status.")
        return "\n".join(lines) + "\n"

    def _block(label: str, items: list[Transition]) -> None:
        if not items:
            return
        lines.append(f"{label} ({len(items)}):")
        for t in items:
            lines.append(f"    {t.check_id:<12} {t.old} → {t.new}")

    _block("✔ fixed", d.fixed)
    _block("✘ regressed", d.regressed)
    _block("… still failing", d.still_failing)
    _block("~ other changes", d.other_changes)
    if d.added:
        lines.append(f"+ added ({len(d.added)}): {', '.join(d.added)}")
    if d.removed:
        lines.append(f"- removed ({len(d.removed)}): {', '.join(d.removed)}")

    lines.append("")
    verdict = "REGRESSIONS" if d.has_regressions else "no regressions"
    lines.append(
        f"Summary: {len(d.fixed)} fixed, {len(d.regressed)} regressed, "
        f"{len(d.still_failing)} still failing, {len(d.added)} added, "
        f"{len(d.removed)} removed — {verdict}."
    )
    return "\n".join(lines) + "\n"
