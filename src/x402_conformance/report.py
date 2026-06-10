"""Report generation: JSON (machine-readable) and Markdown (human-readable)."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone

from . import SPEC_BASELINE, __version__
from .checks import CheckResult, Severity, Status

_GATING = (Severity.CRITICAL, Severity.MAJOR)
_BAD = (Status.FAIL, Status.ERROR)


def summarize(results: list[CheckResult]) -> dict[str, int]:
    return {
        "total": len(results),
        "passed": sum(r.status == Status.PASS for r in results),
        "failed": sum(r.status == Status.FAIL for r in results),
        "skipped": sum(r.status == Status.SKIP for r in results),
        "errors": sum(r.status == Status.ERROR for r in results),
    }


def exit_code(results: list[CheckResult]) -> int:
    """CI gate: 1 if any critical/major check failed or errored, else 0."""
    return int(any(r.status in _BAD and r.severity in _GATING for r in results))


def to_json(results: list[CheckResult], target_url: str) -> str:
    return json.dumps(
        {
            "tool": {"name": "x402-conformance", "version": __version__},
            "specBaseline": SPEC_BASELINE,
            "target": target_url,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": summarize(results),
            "conformant": exit_code(results) == 0,
            "results": [asdict(r) for r in results],
        },
        indent=2,
    )


def to_markdown(results: list[CheckResult], target_url: str) -> str:
    s = summarize(results)
    verdict = "✅ CONFORMANT" if exit_code(results) == 0 else "❌ NOT CONFORMANT"
    lines = [
        "# x402 Conformance Report",
        "",
        f"**Target:** `{target_url}`",
        f"**Verdict:** {verdict} "
        f"({s['passed']} passed, {s['failed']} failed, {s['skipped']} skipped, {s['errors']} errors)",
        f"**Spec baseline:** {SPEC_BASELINE}",
        f"**Generated:** {datetime.now(timezone.utc).isoformat()} by x402-conformance {__version__}",
        "",
        "| ID | Check | Severity | Status | Detail | Spec ref |",
        "|----|-------|----------|--------|--------|----------|",
    ]
    icon = {Status.PASS: "✅", Status.FAIL: "❌", Status.SKIP: "⏭️", Status.ERROR: "💥"}
    for r in results:
        detail = r.detail.replace("|", "\\|") or "—"
        lines.append(
            f"| {r.check_id} | {r.title} | {r.severity.value} "
            f"| {icon[r.status]} {r.status.value} | {detail} | {r.spec_ref} |"
        )
    lines.append("")
    return "\n".join(lines)
