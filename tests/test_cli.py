"""Internal: CLI wiring — commands exist, exit codes are correct, reports written."""

from __future__ import annotations

import json

import httpx
from typer.testing import CliRunner

import x402_conformance.cli as cli
from x402_conformance.checks import CheckResult, Severity, Status

runner = CliRunner()


def _results(status: Status, sev: Severity = Severity.MAJOR):
    return [CheckResult("RS-HS-001", "t", sev, "spec", status, "")]


def test_version_command() -> None:
    result = runner.invoke(cli.app, ["version"])
    assert result.exit_code == 0
    assert "x402-conformance" in result.output
    assert "spec baseline" in result.output


def test_check_conformant_exit_0(monkeypatch) -> None:
    monkeypatch.setattr(cli, "run_checks", lambda *a, **k: _results(Status.PASS))
    result = runner.invoke(cli.app, ["check", "https://t.example"])
    assert result.exit_code == 0
    assert "CONFORMANT" in result.output


def test_check_nonconformant_exit_1(monkeypatch) -> None:
    monkeypatch.setattr(cli, "run_checks", lambda *a, **k: _results(Status.FAIL))
    result = runner.invoke(cli.app, ["check", "https://t.example"])
    assert result.exit_code == 1
    assert "NOT CONFORMANT" in result.output


def test_check_unreachable_exit_2(monkeypatch) -> None:
    def boom(*a, **k):
        raise httpx.ConnectError("no route")

    monkeypatch.setattr(cli, "run_checks", boom)
    result = runner.invoke(cli.app, ["check", "https://t.example"])
    assert result.exit_code == 2
    assert "unreachable" in result.output


def test_server_error_is_unreachable_exit_2(monkeypatch) -> None:
    # T-23: a 5xx endpoint surfaces as EndpointUnreachable (an httpx.HTTPError) and
    # rides the same exit-2 path as a connection failure — not a conformance FAIL.
    from x402_conformance.runner import EndpointUnreachable

    def boom(*a, **k):
        raise EndpointUnreachable("endpoint returned server error HTTP 530 with no x402 paywall")

    monkeypatch.setattr(cli, "run_checks", boom)
    result = runner.invoke(cli.app, ["check", "https://t.example"])
    assert result.exit_code == 2
    assert "unreachable" in result.output


def test_facilitator_url_emits_warning(monkeypatch) -> None:
    # T-24: pointing the passive `check` at a facilitator /supported endpoint warns
    # (it correctly answers 200, not 402) and suggests the facilitator subcommand.
    monkeypatch.setattr(cli, "run_checks", lambda *a, **k: _results(Status.PASS))
    result = runner.invoke(cli.app, ["check", "https://facilitator.x402.rs/supported"])
    assert "facilitator" in result.output.lower()


def test_plain_resource_url_no_facilitator_warning(monkeypatch) -> None:
    monkeypatch.setattr(cli, "run_checks", lambda *a, **k: _results(Status.PASS))
    result = runner.invoke(cli.app, ["check", "https://api.example.com/premium/data"])
    assert "use the 'facilitator' subcommand" not in result.output


def test_check_writes_json_report(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(cli, "run_checks", lambda *a, **k: _results(Status.PASS))
    out = tmp_path / "report.json"
    result = runner.invoke(cli.app, ["check", "https://t.example", "--json", str(out)])
    assert result.exit_code == 0
    doc = json.loads(out.read_text())
    assert doc["target"] == "https://t.example"
    assert doc["conformant"] is True


def test_check_writes_run_record(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(cli, "run_checks", lambda *a, **k: _results(Status.PASS))
    result = runner.invoke(cli.app, ["check", "https://t.example", "--log-dir", str(tmp_path)])
    assert result.exit_code == 0
    assert "Run record:" in result.output
    records = list(tmp_path.glob("run-*.json"))
    assert len(records) == 1
    assert (tmp_path / "runs.jsonl").exists()


def test_logging_is_on_by_default(monkeypatch, tmp_path) -> None:
    # With no flags and the suppression env cleared, a run writes to ./x402-runs.
    monkeypatch.setattr(cli, "run_checks", lambda *a, **k: _results(Status.PASS))
    monkeypatch.delenv("X402_CONFORMANCE_NO_LOG", raising=False)
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(cli.app, ["check", "https://t.example"])
    assert result.exit_code == 0
    assert (tmp_path / "x402-runs" / "runs.jsonl").exists()
    assert list((tmp_path / "x402-runs").glob("run-*.json"))


def test_no_log_flag_suppresses(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(cli, "run_checks", lambda *a, **k: _results(Status.PASS))
    monkeypatch.delenv("X402_CONFORMANCE_NO_LOG", raising=False)
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(cli.app, ["check", "https://t.example", "--no-log"])
    assert result.exit_code == 0
    assert not (tmp_path / "x402-runs").exists()


def test_unreachable_target_is_still_logged(monkeypatch, tmp_path) -> None:
    def boom(*a, **k):
        raise httpx.ConnectError("no route")

    monkeypatch.setattr(cli, "run_checks", boom)
    result = runner.invoke(cli.app, ["check", "https://t.example", "--log-dir", str(tmp_path)])
    assert result.exit_code == 2
    records = list(tmp_path.glob("run-*.json"))
    assert len(records) == 1
    rec = json.loads(records[0].read_text())
    assert rec["error"].startswith("target unreachable")
    assert rec["exitCode"] == 2
    assert rec["conformant"] is False
    assert rec["results"] == []


def test_minor_only_failure_still_exit_0(monkeypatch) -> None:
    monkeypatch.setattr(cli, "run_checks", lambda *a, **k: _results(Status.FAIL, Severity.MINOR))
    result = runner.invoke(cli.app, ["check", "https://t.example"])
    assert result.exit_code == 0


def test_commands_registered() -> None:
    help_out = runner.invoke(cli.app, ["--help"]).output
    for cmd in ("check", "facilitator", "discovery", "version"):
        assert cmd in help_out
