"""Report generation: JSON (machine-readable) and Markdown (human-readable)."""

from __future__ import annotations

import importlib
import json
from dataclasses import asdict, replace
from datetime import UTC, datetime
from typing import Any

from . import SPEC_BASELINE, __version__
from .checks import CheckResult, Severity, Status
from .checks.base import (
    DEFERRED_PENDING_UPSTREAM,
    ENDPOINT_ABSENT,
    INCONCLUSIVE_NO_CHECKS_APPLICABLE,
    INCONCLUSIVE_NOT_X402_V2,
)
from .redaction import sanitize_text, sanitize_url, url_fingerprint

_GATING = (Severity.CRITICAL, Severity.MAJOR)
_BAD = (Status.FAIL, Status.ERROR)

#: Schema version of the JSON report. Bump on any breaking shape change; the
#: contract is pinned in report.schema.json at the repo root.
#: 1.2 adds the optional `results[].reason_code`. 1.3 adds the top-level
#: `inconclusiveReason` (the machine-readable reason an exit-2 verdict is inconclusive)
#: and the `endpoint_absent` per-check reason_code. The schema sets
#: additionalProperties=false, so a new field is a contract change, not a free addition —
#: minor bump, same major, consumers pinning major 1 keep working.
REPORT_VERSION = "1.3"

#: SARIF 2.1.0 — the OASIS static-analysis interchange format GitHub code scanning
#: and bug-bounty platforms ingest. Lets a scan's findings land in a Security tab.
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)
_TOOL_URI = "https://github.com/moped2110/x402-conformance"


def summarize(results: list[CheckResult]) -> dict[str, int]:
    """Count PASS, FAIL, SKIP, and ERROR outcomes for a result set."""
    return {
        "total": len(results),
        "passed": sum(r.status == Status.PASS for r in results),
        "failed": sum(r.status == Status.FAIL for r in results),
        "skipped": sum(r.status == Status.SKIP for r in results),
        "errors": sum(r.status == Status.ERROR for r in results),
    }


def exit_code(results: list[CheckResult]) -> int:
    """CI gate: suite errors always gate; MINOR conformance failures stay advisory."""
    return int(
        any(
            r.status == Status.ERROR or (r.status == Status.FAIL and r.severity in _GATING)
            for r in results
        )
    )


def assessment_exit_code(results: list[CheckResult]) -> int:
    """Return 0/1/2 for conformant/non-conformant/inconclusive evidence."""
    gating = exit_code(results)
    if gating:
        return gating
    if not results or all(result.status is Status.SKIP for result in results):
        return 2
    if any(result.reason_code == DEFERRED_PENDING_UPSTREAM for result in results):
        # We declined to judge a point that would otherwise gate. Certifying
        # conformance on that basis would assert more than we checked.
        return 2
    version = next((r for r in results if r.check_id == "RS-PR-001"), None)
    if version is not None and version.status is not Status.PASS:
        return 2
    return 0


def _inconclusive_reason_from_results(results: list[CheckResult]) -> str:
    """Name why a result set reads as inconclusive, most specific cause first.

    Priority: a wrong/absent endpoint (nothing of the tested kind was there) outranks
    a deferred judgement, which outranks "nothing applied", which outranks a failed
    version check. Callers only use this when the verdict is already exit 2.
    """
    if any(r.reason_code == ENDPOINT_ABSENT for r in results):
        return ENDPOINT_ABSENT
    if any(r.reason_code == DEFERRED_PENDING_UPSTREAM for r in results):
        return DEFERRED_PENDING_UPSTREAM
    if not results or all(r.status is Status.SKIP for r in results):
        return INCONCLUSIVE_NO_CHECKS_APPLICABLE
    return INCONCLUSIVE_NOT_X402_V2


def assessment_reason(results: list[CheckResult], *, override: str | None = None) -> str | None:
    """Return the machine reason an assessment is inconclusive, else None.

    ``override`` lets a caller supply a reason only it can know — the CLI passes
    ``unreachable`` or ``invalid_input`` for outcomes decided before any check ran.
    """
    if assessment_exit_code(results) != 2:
        return None
    return override or _inconclusive_reason_from_results(results)


def _safe_results(results: list[CheckResult], target_url: str) -> list[CheckResult]:
    """Return report-safe result copies with target and URL-bearing details sanitized."""
    return [
        replace(
            result,
            detail=sanitize_text(result.detail, sensitive_values=(target_url,)) or "",
        )
        for result in results
    ]


def to_json(
    results: list[CheckResult],
    target_url: str,
    outcome_code: int | None = None,
    *,
    inconclusive_reason: str | None = None,
) -> str:
    """Render the versioned machine-readable conformance report.

    ``inconclusive_reason`` is a caller-supplied override for exit-2 outcomes the CLI
    decided before running checks (unreachable, invalid input); otherwise the reason is
    derived from the results. It is only emitted when the verdict is exit 2.
    """
    results = _safe_results(results, target_url)
    code = assessment_exit_code(results) if outcome_code is None else outcome_code
    reason = None
    if code == 2:
        reason = inconclusive_reason or _inconclusive_reason_from_results(results)
    return json.dumps(
        {
            "reportVersion": REPORT_VERSION,
            "tool": {"name": "x402-conformance", "version": __version__},
            "specBaseline": SPEC_BASELINE,
            "target": sanitize_url(target_url),
            "targetFingerprint": url_fingerprint(target_url),
            "timestamp": datetime.now(UTC).isoformat(),
            "summary": summarize(results),
            "conformant": code == 0,
            "exitCode": code,
            "inconclusiveReason": reason,
            "results": [asdict(r) for r in results],
        },
        indent=2,
    )


def _sarif_level(severity: Severity) -> str:
    """Map our severity to a SARIF result level. Gating (critical/major) → ``error``
    so it surfaces as a code-scanning alert; advisory (minor) → ``warning``."""
    return "warning" if severity is Severity.MINOR else "error"


def to_sarif(results: list[CheckResult], target_url: str, outcome_code: int | None = None) -> str:
    """Emit the run's findings as SARIF 2.1.0 (machine-readable, GitHub-ingestible).

    Findings only — FAIL and ERROR results — since SARIF is an alert format: a passing
    or skipped check is not an alert. Each finding references a rule (the check) carrying
    its title, spec ref, severity and remediation hint. The scanned endpoint is the
    ``artifactLocation``; ``partialFingerprints`` gives each finding a stable identity so
    a platform can dedupe it across runs.
    """
    results = _safe_results(results, target_url)
    safe_target = sanitize_url(target_url) or "<redacted>"
    code = assessment_exit_code(results) if outcome_code is None else outcome_code
    findings = [r for r in results if r.status in _BAD]

    rules: list[dict[str, Any]] = []
    seen: set[str] = set()
    for r in findings:
        if r.check_id in seen:
            continue
        seen.add(r.check_id)
        rule: dict[str, Any] = {
            "id": r.check_id,
            "name": r.check_id.replace("-", ""),
            "shortDescription": {"text": r.title},
            "defaultConfiguration": {"level": _sarif_level(r.severity)},
            "properties": {
                "severity": r.severity.value,
                "specRef": r.spec_ref,
                "tags": ["x402", "conformance", r.severity.value],
            },
        }
        fix = _REMEDIATION.get(r.check_id)
        if fix:
            rule["fullDescription"] = {"text": fix}
            rule["help"] = {"text": fix}
        rules.append(rule)

    sarif_results: list[dict[str, Any]] = []
    for r in findings:
        message = f"{r.title}: {r.detail}" if r.detail else r.title
        sarif_results.append(
            {
                "ruleId": r.check_id,
                "level": _sarif_level(r.severity),
                "message": {"text": message},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": safe_target}}}],
                "partialFingerprints": {
                    "x402ConformanceCheckId": f"{r.check_id}@{url_fingerprint(target_url)}"
                },
                "properties": {
                    "severity": r.severity.value,
                    "status": r.status.value,
                    "specRef": r.spec_ref,
                },
            }
        )

    doc: dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "x402-conformance",
                        "version": __version__,
                        "informationUri": _TOOL_URI,
                        "rules": rules,
                    }
                },
                "results": sarif_results,
                "properties": {
                    "target": safe_target,
                    "targetFingerprint": url_fingerprint(target_url),
                    "specBaseline": SPEC_BASELINE,
                    "conformant": code == 0,
                    "exitCode": code,
                },
            }
        ],
    }
    return json.dumps(doc, indent=2)


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


def to_markdown(
    results: list[CheckResult], target_url: str, outcome_code: int | None = None
) -> str:
    """Render a sanitized human-readable Markdown conformance report."""
    results = _safe_results(results, target_url)
    code = assessment_exit_code(results) if outcome_code is None else outcome_code
    s = summarize(results)
    verdict = (
        "✅ CONFORMANT" if code == 0 else "⚠️ INCONCLUSIVE" if code == 2 else "❌ NOT CONFORMANT"
    )
    lines = [
        "# x402 Conformance Report",
        "",
        f"**Target:** `{_md_inline_code(sanitize_url(target_url) or '<redacted>')}`",
        f"**Verdict:** {verdict} "
        f"({s['passed']} passed, {s['failed']} failed, {s['skipped']} skipped, {s['errors']} errors)",
        f"**Spec baseline:** {SPEC_BASELINE}",
        f"**Generated:** {datetime.now(UTC).isoformat()} by x402-conformance {__version__}",
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


# Crisp, developer-facing remediation hints keyed by check id. Not every check needs
# one — the check's own `detail` already says what's wrong; this adds the "how to fix"
# for the high-value cases. Unmapped checks fall back to detail + spec ref.
_REMEDIATION: dict[str, str] = {
    "RS-HS-001": "Return HTTP 402 for an unpaid request; never serve protected content without payment.",
    "RS-HS-002": "Include the PAYMENT-REQUIRED header (base64 PaymentRequired) on the 402 response.",
    "RS-HS-007": "Send `Cache-Control: no-store` on the 402 so a CDN/proxy can't serve the paywall to others.",
    "RS-PR-001": "Emit `x402Version: 2` (this suite tests v2; a recognised v1 endpoint is reported separately).",
    "RS-PR-002": "Include a top-level `resource` object with a non-empty `url`.",
    "RS-PR-005": "Give every `accepts` entry all required fields: scheme, network, amount, asset, payTo, maxTimeoutSeconds.",
    "RS-PR-006": "Use a CAIP-2 network id (e.g. `eip155:8453`), not a legacy name like `base-sepolia`.",
    "RS-PR-007": "Express `amount` as an integer string in atomic units (no decimal point).",
    "RS-PR-009": "Add `extra.name` and `extra.version` to each exact/eip3009 entry — clients need them to build the EIP-712 domain.",
    "RS-PR-013": "Match payTo/asset to the network namespace (EVM address for eip155, Solana address for solana).",
    "RS-PR-014": "Set a strictly positive `amount` (> 0).",
    "RS-NEG-003": "Reject a payment whose signature doesn't recover to `from` before serving or settling.",
    "RS-NEG-005": "Reject underpayment: the authorized value must equal the required amount.",
    "RS-NEG-007": "Reject a payment whose `to` doesn't match your payTo (recipient mismatch).",
    "RS-NEG-008": "Reject expired authorizations (validBefore in the past).",
    "RS-NEG-013": "Validate the price against YOUR requirements, not the client-supplied `accepted` amount.",
    "RS-NEG-014": "Verify the asset is your expected token contract, not any address the client supplies.",
    "RS-NEG-015": "Reject an asset with no contract code (an EOA): settling against it is a silent no-op — pre-flight `eth_getCode`.",
    "RS-SEC-003": "Bind each payment to the requested resource — reject a payment whose claimed `resource` differs from the one being served.",
    "RS-SEC-006": "Validate one header deterministically — never let a legacy X-PAYMENT header bypass v2 validation, and don't 5xx on duplicate/contradictory payment headers.",
    "RS-SEC-010": "Bind to the EIP-712 chainId and reject cross-chain-replayed signatures.",
    "RS-SEC-011": "Handle an extreme (2²⁵⁶-1) amount cleanly — reject it, don't 5xx-crash.",
    "FA-SUP-001": "If you expose /supported, return `kinds[]`, `extensions[]`, `signers{}` (it's optional — omitting it is fine).",
    "FA-VER-002": "Your /verify must return `isValid:false` (with a CORE §9 reason) for an invalid payment.",
    "FA-VER-003": "Reject an asset that is an EOA (no bytecode) with `asset_not_deployed_contract`.",
    "FA-VER-004": "Return isValid:false (200/4xx) on invalid input — don't let a balanceOf/parse exception bubble up to a 5xx.",
    "FA-SET-003": "Reject a double-settle of the same payment (nonce reuse).",
    "RS-SEC-009": "Never echo the protected resource on a rejection path — the 402 body must not leak paid content.",
    "DI-003": "Keep the discovery listing in sync with each resource's live 402 — the listed asset/payTo must match what the resource actually asks for.",
}

_SEVERITY_HEADER = {
    Severity.CRITICAL: "CRITICAL — must fix (security / funds at risk)",
    Severity.MAJOR: "MAJOR — spec violation / interop broken",
    Severity.MINOR: "MINOR — advisory",
}

# On-chain / settle checks that don't live in a decorator registry — they run via the
# --pay (RS-PAY / RS-SEC-001/002) and `facilitator --settle` (FA-SET) paths. Listed here
# so `explain` can describe them too. Metadata mirrors docs/conformance-catalog.md; keep
# in sync if those checks change (they are stable, so drift risk is low).
_ONCHAIN_CHECKS: list[tuple[str, str, Severity, str]] = [
    (
        "RS-PAY-001",
        "Valid funded payment is accepted and the resource delivered",
        Severity.CRITICAL,
        "CORE §2, HTTP",
    ),
    (
        "RS-PAY-002",
        "Success response carries a valid PAYMENT-RESPONSE settlement",
        Severity.MAJOR,
        "HTTP §Settlement Response Delivery",
    ),
    ("RS-PAY-003", "Settlement network and payer match the payment", Severity.MAJOR, "CORE §5.3.2"),
    (
        "RS-PAY-004",
        "Settlement transaction proves the expected on-chain transfer",
        Severity.CRITICAL,
        "CORE §6.1.3",
    ),
    (
        "RS-SEC-001",
        "Replaying a settled payment is rejected (nonce reuse)",
        Severity.CRITICAL,
        "CORE §10.1",
    ),
    (
        "RS-SEC-002",
        "Concurrent settle of one payment yields at most one success (race)",
        Severity.CRITICAL,
        "CORE §10.1",
    ),
    (
        "FA-SET-001",
        "/settle of a valid payment succeeds with a tx hash",
        Severity.MAJOR,
        "CORE §7.2",
    ),
    (
        "FA-SET-002",
        "/settle of an invalid payment fails with an empty tx",
        Severity.MAJOR,
        "CORE §7.2",
    ),
    (
        "FA-SET-003",
        "Double-settle of the same payment is rejected (nonce reuse)",
        Severity.CRITICAL,
        "CORE §10.1",
    ),
    (
        "RS-SEC-008",
        "Rejection timing does not leak the rejection reason (timing oracle)",
        Severity.MINOR,
        "CORE §10.1",
    ),
]


def _explain_catalog() -> dict[str, tuple[str, Severity, str]]:
    """Every check the suite ships, as ``check_id -> (title, severity, spec_ref)``.

    Collects the passive REGISTRY plus the active / facilitator / discovery registries
    (imported defensively so `explain` still works without the ``[evm]`` extra, which the
    active checks need), plus the on-chain/settle checks that aren't in a registry.
    """
    from .checks import REGISTRY  # passive checks — always importable

    entries = list(REGISTRY)
    for modname, attr in (
        ("negative", "ACTIVE_REGISTRY"),
        ("facilitator", "FA_REGISTRY"),
        ("discovery", "DI_REGISTRY"),
    ):
        try:
            mod = importlib.import_module(f".checks.{modname}", package=__package__)
            entries.extend(getattr(mod, attr))
        except Exception:
            continue  # e.g. active checks unavailable without [evm]; skip gracefully
    catalog: dict[str, tuple[str, Severity, str]] = {
        c.check_id: (c.title, c.severity, c.spec_ref) for c in entries
    }
    for cid, title, sev, ref in _ONCHAIN_CHECKS:
        catalog.setdefault(cid, (title, sev, ref))
    return catalog


def _explain_line(cid: str, title: str, sev: Severity) -> str:
    """Format one compact check-catalog entry for explain output."""
    return f"  {cid:<12} [{sev.value:<8}] {title}"


def explain_check(query: str | None) -> str:
    """Explain a check ID in plain language, or list the catalog.

    No ``query`` → the full catalog (id, severity, title). An exact ID → its title,
    severity meaning, spec reference, and a fix hint where we have one. A partial/prefix
    string → the matching IDs. Case-insensitive.
    """
    catalog = _explain_catalog()
    if not query:
        lines = ["x402-conformance — check catalog", ""]
        lines += [_explain_line(cid, catalog[cid][0], catalog[cid][1]) for cid in sorted(catalog)]
        lines += ["", "Run `x402-conformance explain <CHECK-ID>` for one check in detail."]
        return "\n".join(lines)

    q = query.strip().upper()
    if q in catalog:
        title, sev, ref = catalog[q]
        lines = [
            f"{q} — {title}",
            f"  severity: {_SEVERITY_HEADER[sev]}",
            f"  spec ref: {ref}",
        ]
        fix = _REMEDIATION.get(q)
        if fix:
            lines.append(f"  fix:      {fix}")
        return "\n".join(lines)

    matches = sorted(cid for cid in catalog if q in cid)
    if not matches:
        return (
            f"no check matches {query!r}. Run `x402-conformance explain` with no "
            "argument to list every check ID."
        )
    header = f"{len(matches)} checks match {query!r}:"
    body = [_explain_line(cid, catalog[cid][0], catalog[cid][1]) for cid in matches]
    return "\n".join([header, "", *body])


def to_developer_report(
    results: list[CheckResult], target_url: str, outcome_code: int | None = None
) -> str:
    """A developer-facing punch-list for the endpoint owner under test.

    Failures only (FAIL/ERROR), grouped by severity, each with what's wrong
    (`detail`), how to fix (a remediation hint where we have one), and the spec
    reference. Plain text, meant to be read straight from a test run.
    """
    results = _safe_results(results, target_url)
    code = assessment_exit_code(results) if outcome_code is None else outcome_code
    failures = [r for r in results if r.status in _BAD]
    s = summarize(results)
    lines = [
        "x402 conformance — developer report",
        f"Target: {sanitize_url(target_url) or '<redacted>'}",
        "",
    ]
    if not failures:
        if code == 2:
            lines.append(
                f"⚠️ INCONCLUSIVE — insufficient mandatory evidence. "
                f"{s['passed']} passed, {s['skipped']} skipped."
            )
        else:
            lines.append(
                f"✅ CONFORMANT — no issues to fix. {s['passed']} passed, {s['skipped']} skipped."
            )
        return "\n".join(lines) + "\n"

    gating = [r for r in failures if r.status == Status.ERROR or r.severity in _GATING]
    advisory = len(failures) - len(gating)
    verdict = (
        "INCONCLUSIVE"
        if code == 2
        else "NOT CONFORMANT"
        if gating
        else "CONFORMANT (advisory issues only)"
    )
    lines.append(
        f"{verdict} — {len(gating)} blocking, {advisory} advisory "
        f"(of {s['total']} checks: {s['passed']} passed, {s['skipped']} skipped)"
    )
    lines.append("")
    for severity in (Severity.CRITICAL, Severity.MAJOR, Severity.MINOR):
        group = [r for r in failures if r.severity == severity]
        if not group:
            continue
        lines.append(_SEVERITY_HEADER[severity])
        for r in group:
            lines.append(f"  ✗ {r.check_id}  {r.title}")
            if r.detail:
                lines.append(f"      what: {r.detail}")
            fix = _REMEDIATION.get(r.check_id)
            if fix:
                lines.append(f"      fix:  {fix}")
            lines.append(f"      spec: {r.spec_ref}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
