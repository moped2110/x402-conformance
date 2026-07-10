"""Tests for structured, tamper-evident run records."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from x402_conformance.checks import CheckResult, Severity, Status
from x402_conformance.run_record import (
    _clean_inputs,
    _redact_url,
    build_run_record,
    verify_run_record,
    write_run_record,
)


def _results() -> list[CheckResult]:
    return [
        CheckResult("RS-HS-001", "handshake", Severity.MAJOR, "spec", Status.PASS, ""),
        CheckResult("RS-NEG-004", "foreign sig", Severity.CRITICAL, "spec", Status.FAIL, "served"),
    ]


def _record():
    start = datetime(2026, 7, 9, 12, 0, 0, tzinfo=UTC)
    end = datetime(2026, 7, 9, 12, 0, 3, tzinfo=UTC)
    return build_run_record(
        command="check",
        target="https://api.example.com/data",
        inputs={"method": "GET", "active": True, "rpc_url": None, "signer_key": "0xDEAD"},
        results=_results(),
        signer_address="0x1111111111111111111111111111111111111111",
        started_at=start,
        finished_at=end,
    )


def test_record_has_core_fields_and_hash() -> None:
    rec = _record()
    assert rec["command"] == "check"
    assert rec["target"] == "https://api.example.com/data"
    assert rec["tool"]["name"] == "x402-conformance"
    assert rec["startedAt"] == "2026-07-09T12:00:00+00:00"
    assert rec["durationSeconds"] == 3.0
    assert rec["summary"]["passed"] == 1
    assert rec["summary"]["failed"] == 1
    assert rec["summary"]["skipped"] == 0
    assert rec["summary"]["errors"] == 0
    assert rec["conformant"] is False  # a CRITICAL fail
    assert rec["exitCode"] == 1
    assert rec["signerAddress"] == "0x1111111111111111111111111111111111111111"
    assert rec["runId"].startswith("sha256:")
    assert len(rec["results"]) == 2


def test_inputs_never_persist_a_key() -> None:
    rec = _record()
    # signer_key must be dropped; None values dropped.
    assert "signer_key" not in rec["inputs"]
    assert "rpc_url" not in rec["inputs"]  # was None → dropped
    assert rec["inputs"]["method"] == "GET"


def test_verify_detects_tampering() -> None:
    rec = _record()
    assert verify_run_record(rec) is True
    # Flip a verdict — the hash no longer matches.
    rec["results"][1]["status"] = "pass"
    assert verify_run_record(rec) is False


def test_redact_url_strips_provider_key() -> None:
    # A key embedded in the path or query must not survive.
    assert _redact_url("https://base-mainnet.g.alchemy.com/v2/SECRETKEY") == (
        "https://base-mainnet.g.alchemy.com"
    )
    assert _redact_url("https://rpc.example.com:8545/?apikey=abc") == "https://rpc.example.com:8545"
    assert _redact_url(None) is None


def test_clean_inputs_redacts_rpc_and_drops_secrets() -> None:
    cleaned = _clean_inputs(
        {
            "rpc_url": "https://node.example/v2/KEY",
            "signer_key": "0xabc",
            "password": "hunter2",
            "method": "POST",
            "timeout": None,
        }
    )
    assert cleaned == {"rpc_url": "https://node.example", "method": "POST"}


def test_write_run_record_writes_file_and_journal(tmp_path) -> None:
    rec = _record()
    path = write_run_record(rec, tmp_path)
    assert path.exists()
    on_disk = json.loads(path.read_text())
    assert verify_run_record(on_disk) is True  # survives a round-trip

    journal = (tmp_path / "runs.jsonl").read_text().strip().splitlines()
    assert len(journal) == 1
    line = json.loads(journal[0])
    assert line["runId"] == rec["runId"]
    assert line["file"] == path.name
    assert line["conformant"] is False
    # The journal is what you grep — it must carry the verdict itself, not just
    # ``conformant``. Regression guard for T-22 (VPS run 2026-07-09: exitCode/error
    # were absent from the index while the full record had them).
    assert line["exitCode"] == 1
    assert line["error"] is None


def test_journal_carries_exitcode_and_error_for_unreachable_run(tmp_path) -> None:
    # A target that never answered is recorded with an error and exit 2. The
    # journal line must surface both so an unreachable run is greppable without
    # opening the full record.
    start = datetime(2026, 7, 9, 12, 0, 0, tzinfo=UTC)
    rec = build_run_record(
        command="check",
        target="https://down.example.com/data",
        inputs={"method": "GET"},
        results=[],
        signer_address=None,
        started_at=start,
        finished_at=start,
        error="connection refused",
        override_exit_code=2,
    )
    write_run_record(rec, tmp_path)
    line = json.loads((tmp_path / "runs.jsonl").read_text().strip())
    assert line["exitCode"] == 2
    assert line["error"] == "connection refused"
    assert line["conformant"] is False


def test_journal_appends_across_runs(tmp_path) -> None:
    write_run_record(_record(), tmp_path)
    write_run_record(_record(), tmp_path)
    lines = (tmp_path / "runs.jsonl").read_text().strip().splitlines()
    assert len(lines) == 2  # appended, not overwritten
