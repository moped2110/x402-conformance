"""Internal: CLI wiring — commands exist, exit codes are correct, reports written."""

from __future__ import annotations

import json

import httpx
import pytest
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


def test_check_writes_json_report(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(cli, "run_checks", lambda *a, **k: _results(Status.PASS))
    out = tmp_path / "report.json"
    result = runner.invoke(cli.app, ["check", "https://t.example", "--json", str(out)])
    assert result.exit_code == 0
    doc = json.loads(out.read_text())
    assert doc["target"] == "https://t.example"
    assert doc["conformant"] is True


def test_minor_only_failure_still_exit_0(monkeypatch) -> None:
    monkeypatch.setattr(cli, "run_checks", lambda *a, **k: _results(Status.FAIL, Severity.MINOR))
    result = runner.invoke(cli.app, ["check", "https://t.example"])
    assert result.exit_code == 0


def test_commands_registered() -> None:
    help_out = runner.invoke(cli.app, ["--help"]).output
    for cmd in ("check", "facilitator", "discovery", "version"):
        assert cmd in help_out
