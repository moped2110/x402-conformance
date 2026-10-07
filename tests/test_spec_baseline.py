"""SPEC_BASELINE must name the upstream review the repository actually records.

v0.7.0 shipped with `x402-conformance version`, and every report and run record,
claiming "upstream reviewed through f62a9fa (2026-08-13)" after the 2026-10 review
had moved the pin to cb0ec5b. The pin lives in `.github/upstream-reviewed-commit`
and its date in `docs/support-matrix.md`; this test ties the constant to both.
"""

from __future__ import annotations

import re
from pathlib import Path

from x402_conformance import SPEC_BASELINE

ROOT = Path(__file__).resolve().parents[1]


def test_spec_baseline_names_the_recorded_upstream_review() -> None:
    """The constant's 'reviewed through <sha> (<date>)' matches the recorded pin."""
    pinned = (ROOT / ".github" / "upstream-reviewed-commit").read_text().strip()
    matrix = (ROOT / "docs" / "support-matrix.md").read_text(encoding="utf-8")
    line = re.search(
        r"\*\*Latest upstream review:\*\* `main@([0-9a-f]+)` \((\d{4}-\d{2}-\d{2})\)", matrix
    )
    assert line is not None, "support-matrix.md lost its 'Latest upstream review' line"
    assert line.group(1) == pinned, "support matrix and upstream-reviewed-commit disagree"
    assert f"upstream reviewed through {pinned} ({line.group(2)})" in SPEC_BASELINE
