"""Structured run records with an integrity checksum for traceability.

Console output is ephemeral. For an audit trail we persist every run as a JSON
record — a UTC timestamp, the tool + spec version, the exact invocation inputs,
the environment, the full per-check results and the verdict — plus a one-line
append to a JSONL journal so a directory of runs stays greppable.

A content hash over the canonical record (``runId``) is an integrity checksum: changes are
detectable by re-hashing the file and comparing the digest. No secrets ever land in a record — only
the signer's *public* address is stored (never a key), and an ``rpc_url`` is
reduced to scheme+host so a provider key embedded in its path/query can't leak.
This checksum is not an adversarial trust anchor: an editor can recompute it.
"""

from __future__ import annotations

import hashlib
import json
import platform
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import SPEC_BASELINE, __version__
from .checks import CheckResult
from .redaction import sanitize_text, sanitize_url, url_fingerprint
from .report import assessment_exit_code, summarize

SCHEMA_VERSION = "1.0"

#: Default directory for run records (relative to the current working dir). Logging
#: is on by default; disable per run with ``--no-log`` or the env var below.
DEFAULT_LOG_DIR = "x402-runs"
#: Set this env var (to anything) to suppress the *default* run log — an explicit
#: ``--log-dir`` still writes. Used by the test suite to avoid polluting the tree.
NO_LOG_ENV = "X402_CONFORMANCE_NO_LOG"


def _redact_url(url: str | None) -> str | None:
    """Keep only scheme://host of an RPC URL — providers embed API keys in the
    path (``/v2/<KEY>``) or query, which must never be persisted."""
    return sanitize_url(url)


def _clean_inputs(inputs: dict[str, Any]) -> dict[str, Any]:
    """Drop None values and anything key-shaped; redact rpc_url. Defensive even if
    a caller passes a secret it shouldn't."""
    out: dict[str, Any] = {}
    for k, v in inputs.items():
        if v is None:
            continue
        if "key" in k.lower() or "secret" in k.lower() or "password" in k.lower():
            continue
        if k in ("rpc_url", "rpcUrl"):
            out[k] = _redact_url(str(v))
        else:
            out[k] = v
    return out


def _content_hash(record: dict[str, Any]) -> str:
    payload = {k: v for k, v in record.items() if k != "runId"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


def build_run_record(
    *,
    command: str,
    target: str,
    inputs: dict[str, Any],
    results: list[CheckResult],
    signer_address: str | None,
    started_at: datetime,
    finished_at: datetime,
    error: str | None = None,
    override_exit_code: int | None = None,
) -> dict[str, Any]:
    """Assemble the full, self-describing record for one run (adds ``runId``).

    A run that never produced results — e.g. the target was unreachable — is still
    recorded: pass ``error`` (a message) and ``override_exit_code`` (2). Such a run
    is never ``conformant`` and its ``results`` are simply empty.
    """
    ec = override_exit_code if override_exit_code is not None else assessment_exit_code(results)
    record: dict[str, Any] = {
        "schemaVersion": SCHEMA_VERSION,
        "tool": {
            "name": "x402-conformance",
            "version": __version__,
            "specBaseline": SPEC_BASELINE,
        },
        "command": command,
        "target": sanitize_url(target),
        "targetFingerprint": url_fingerprint(target),
        "startedAt": started_at.astimezone(UTC).isoformat(),
        "finishedAt": finished_at.astimezone(UTC).isoformat(),
        "durationSeconds": round((finished_at - started_at).total_seconds(), 3),
        "inputs": _clean_inputs(inputs),
        "signerAddress": signer_address,  # public address only; never a key
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "machine": platform.machine(),
        },
        "summary": summarize(results),
        "conformant": error is None and ec == 0,
        "exitCode": ec,
        "error": sanitize_text(error, sensitive_values=(target,)),
        "results": [
            {
                **asdict(r),
                "detail": sanitize_text(r.detail, sensitive_values=(target,)) or "",
            }
            for r in results
        ],
    }
    record["runId"] = _content_hash(record)
    return record


def verify_run_record(record: dict[str, Any]) -> bool:
    """True iff content matches its embedded integrity checksum.

    This detects accidental edits only; an adversarial editor can recompute it.
    """
    claimed = record.get("runId")
    return isinstance(claimed, str) and claimed == _content_hash(record)


def write_run_record(record: dict[str, Any], log_dir: Path) -> Path:
    """Write the record as a timestamped JSON file and append a one-line summary
    to ``runs.jsonl`` in the same directory. Returns the JSON file path."""
    log_dir.mkdir(parents=True, exist_ok=True)
    ts = record["startedAt"].replace(":", "").replace("-", "").replace(".", "")
    short = record["runId"].removeprefix("sha256:")[:12]
    path = log_dir / f"run-{ts}-{short}.json"
    path.write_text(json.dumps(record, indent=2), encoding="utf-8")

    # The journal is what you grep to find failing/unreachable runs, so it must
    # carry the verdict itself — not just ``conformant``. ``exitCode`` disambiguates
    # 0 (conformant) / 1 (check failures) / 2 (unreachable or error), and ``error``
    # surfaces the reason for an exit-2 run without opening the full record.
    journal_line = {
        "runId": record["runId"],
        "startedAt": record["startedAt"],
        "command": record["command"],
        "target": record["target"],
        "conformant": record["conformant"],
        "exitCode": record["exitCode"],
        "error": record["error"],
        "summary": record["summary"],
        "file": path.name,
    }
    with (log_dir / "runs.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(journal_line) + "\n")
    return path
