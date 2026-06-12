"""Report generation: JSON (machine-readable) and Markdown (human-readable)."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone

from . import SPEC_BASELINE, __version__
from .checks import CheckResult, Severity, Status

_GATING = (Severity.CRITICAL, Severity.MAJOR)
_BAD = (Status.FAIL, Status.ERROR)

#: Schema version of the JSON report. Bump on any breaking shape change; the
#: contract is pinned in report.schema.json at the repo root.
REPORT_VERSION = "1.0"


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
            "reportVersion": REPORT_VERSION,
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


def _md_cell(text: str) -> str:
    """Neutralize a (possibly endpoint-controlled) string for a Markdown table cell.

    `detail` carries error reasons and other content echoed from the target, so a
    hostile endpoint could otherwise inject raw HTML, links, or table/structure
    breaks into an operator's report. Collapse line breaks (they'd break the row)
    and escape the table/Markdown/HTML metacharacters that matter.
    """
    text = text.replace("\\", "\\\\")
    for ws in ("\r\n", "\r", "\n", "\t"):
        text = text.replace(ws, " ")
    text = text.replace("|", "\\|")
    text = text.replace("<", "&lt;").replace(">", "&gt;")
    text = text.replace("`", "\\`")
    text = text.replace("[", "\\[").replace("]", "\\]")
    return text


def _md_inline_code(text: str) -> str:
    """Sanitize a value rendered inside an inline-code span (e.g. the target URL):
    code spans don't render entities, so just drop backticks and line breaks."""
    for ws in ("\r\n", "\r", "\n", "\t"):
        text = text.replace(ws, " ")
    return text.replace("`", "")


def to_markdown(results: list[CheckResult], target_url: str) -> str:
    s = summarize(results)
    verdict = "✅ CONFORMANT" if exit_code(results) == 0 else "❌ NOT CONFORMANT"
    lines = [
        "# x402 Conformance Report",
        "",
        f"**Target:** `{_md_inline_code(target_url)}`",
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
        detail = _md_cell(r.detail) or "—"
        lines.append(
            f"| {_md_cell(r.check_id)} | {_md_cell(r.title)} | {r.severity.value} "
            f"| {icon[r.status]} {r.status.value} | {detail} | {_md_cell(r.spec_ref)} |"
        )
    lines.append("")
    return "\n".join(lines)
