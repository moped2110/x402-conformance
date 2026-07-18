"""The CLI's exit codes are a documented contract (0 conformant / 1 not / 2
unreachable). ``cli.py`` was the least-covered module; these tests pin every
command's exit code so a refactor can't silently break what CI consumers rely on.

Network is never touched: the runner functions are monkeypatched to return
crafted results or raise, so these stay offline and fast.
"""

from __future__ import annotations

import httpx
from typer.testing import CliRunner

from x402_conformance.checks import CheckResult, Severity, Status
from x402_conformance.cli import app

runner = CliRunner()


def _result(status: Status, severity: Severity) -> CheckResult:
    return CheckResult(
        check_id="RS-HS-001",
        title="dummy",
        severity=severity,
        spec_ref="x402-specification-v2.md",
        status=status,
        detail="",
    )


# --- version / explain: always exit 0, offline -----------------------------


def test_version_exits_zero() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "x402-conformance" in result.stdout


def test_explain_catalog_exits_zero() -> None:
    result = runner.invoke(app, ["explain"])
    assert result.exit_code == 0


def test_explain_single_check_exits_zero() -> None:
    result = runner.invoke(app, ["explain", "RS-NEG-007"])
    assert result.exit_code == 0


# --- check: 0 conformant / 1 not conformant / 2 unreachable -----------------


def test_check_conformant_exits_zero(monkeypatch) -> None:
    monkeypatch.setattr(
        "x402_conformance.cli.run_checks",
        lambda *a, **k: [_result(Status.PASS, Severity.MAJOR)],
    )
    result = runner.invoke(app, ["check", "http://example.test/"])
    assert result.exit_code == 0
    assert "CONFORMANT" in result.stdout


def test_check_major_failure_exits_one(monkeypatch) -> None:
    monkeypatch.setattr(
        "x402_conformance.cli.run_checks",
        lambda *a, **k: [_result(Status.FAIL, Severity.MAJOR)],
    )
    result = runner.invoke(app, ["check", "http://example.test/"])
    assert result.exit_code == 1
    assert "NOT CONFORMANT" in result.stdout


def test_check_minor_failure_still_exits_zero(monkeypatch) -> None:
    # A MINOR failure is advisory — must NOT gate the build.
    monkeypatch.setattr(
        "x402_conformance.cli.run_checks",
        lambda *a, **k: [_result(Status.FAIL, Severity.MINOR)],
    )
    result = runner.invoke(app, ["check", "http://example.test/"])
    assert result.exit_code == 0


def test_check_unreachable_exits_two(monkeypatch) -> None:
    def _boom(*a, **k):
        raise httpx.ConnectError("refused")

    monkeypatch.setattr("x402_conformance.cli.run_checks", _boom)
    result = runner.invoke(app, ["check", "http://example.test/"])
    assert result.exit_code == 2


def test_check_all_skip_is_inconclusive_exit_two(monkeypatch) -> None:
    monkeypatch.setattr(
        "x402_conformance.cli.run_checks",
        lambda *a, **k: [_result(Status.SKIP, Severity.MAJOR)],
    )
    result = runner.invoke(app, ["check", "http://example.test/"])
    assert result.exit_code == 2
    assert "INCONCLUSIVE" in result.stdout


def test_v1_only_check_is_not_reported_as_v2_conformant(monkeypatch) -> None:
    v1 = CheckResult("RS-PR-001", "version", Severity.MAJOR, "spec", Status.SKIP, "v1 endpoint")
    rail = CheckResult("RS-PR-006", "network", Severity.MAJOR, "spec", Status.PASS, "")
    monkeypatch.setattr("x402_conformance.cli.run_checks", lambda *a, **k: [v1, rail])
    result = runner.invoke(app, ["check", "http://example.test/"])
    assert result.exit_code == 2
    assert "INCONCLUSIVE" in result.stdout


# --- facilitator / discovery: unreachable -> 2 ------------------------------


def test_facilitator_unreachable_exits_two(monkeypatch) -> None:
    def _boom(*a, **k):
        raise httpx.ConnectError("refused")

    monkeypatch.setattr("x402_conformance.checks.facilitator.run_facilitator_checks", _boom)
    result = runner.invoke(app, ["facilitator", "http://example.test/"])
    assert result.exit_code == 2


def test_facilitator_all_skip_is_inconclusive_exit_two(monkeypatch) -> None:
    monkeypatch.setattr(
        "x402_conformance.checks.facilitator.run_facilitator_checks",
        lambda *a, **k: [_result(Status.SKIP, Severity.MAJOR)],
    )
    result = runner.invoke(app, ["facilitator", "http://example.test/"])
    assert result.exit_code == 2


def test_discovery_conformant_exits_zero(monkeypatch) -> None:
    monkeypatch.setattr(
        "x402_conformance.checks.discovery.run_discovery_checks",
        lambda *a, **k: [_result(Status.PASS, Severity.MINOR)],
    )
    result = runner.invoke(app, ["discovery", "http://example.test/"])
    assert result.exit_code == 0


# --- diff / scan: read/precondition errors -> 2 -----------------------------


def test_diff_missing_files_exits_two(tmp_path) -> None:
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"  # neither exists
    result = runner.invoke(app, ["diff", str(old), str(new)])
    assert result.exit_code == 2


def test_scan_empty_file_exits_two(tmp_path) -> None:
    targets = tmp_path / "targets.txt"
    targets.write_text("# only a comment\n\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(targets)])
    assert result.exit_code == 2


def test_scan_missing_file_exits_two(tmp_path) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path / "missing.txt")])
    assert result.exit_code == 2
    assert "cannot read targets file" in result.stdout + result.stderr


def test_scan_resource_requires_explicit_active_authorization(tmp_path) -> None:
    targets = tmp_path / "targets.txt"
    targets.write_text("http://127.0.0.1:4021\n", encoding="utf-8")
    result = runner.invoke(
        app,
        ["scan", str(targets), "--resource", "http://127.0.0.1:4022/data"],
    )
    assert result.exit_code == 2
    assert "--authorize-active-verify" in result.stdout + result.stderr


def test_scan_all_targets_unreachable_exits_two(monkeypatch, tmp_path) -> None:
    targets = tmp_path / "targets.txt"
    targets.write_text("http://127.0.0.1:4021\n", encoding="utf-8")

    def _boom(*_args, **_kwargs):
        raise httpx.ConnectError("refused")

    monkeypatch.setattr("x402_conformance.checks.facilitator.run_facilitator_checks", _boom)
    result = runner.invoke(app, ["scan", str(targets)])
    assert result.exit_code == 2


def test_report_write_failure_exits_two(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        "x402_conformance.cli.run_checks",
        lambda *a, **k: [_result(Status.PASS, Severity.MAJOR)],
    )
    result = runner.invoke(
        app,
        ["check", "http://example.test/", "--json", str(tmp_path)],
    )
    assert result.exit_code == 2
    assert "cannot write JSON report" in result.stdout + result.stderr


def test_run_record_write_failure_exits_two(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        "x402_conformance.cli.run_checks",
        lambda *a, **k: [_result(Status.PASS, Severity.MAJOR)],
    )
    invalid_log_dir = tmp_path / "not-a-directory"
    invalid_log_dir.write_text("occupied", encoding="utf-8")
    result = runner.invoke(
        app,
        ["check", "http://example.test/", "--log-dir", str(invalid_log_dir)],
    )
    assert result.exit_code == 2
    assert "cannot write run record" in result.stdout + result.stderr


def test_invalid_signer_key_is_a_usage_error(monkeypatch) -> None:
    monkeypatch.setattr("x402_conformance.active.preflight_resource_network", lambda *a, **k: None)
    result = runner.invoke(
        app,
        [
            "facilitator",
            "http://127.0.0.1:4021",
            "--resource",
            "http://127.0.0.1:4022/data",
            "--signer-key",
            "definitely-not-a-private-key",
        ],
    )
    assert result.exit_code == 2
    assert "invalid EVM testnet signer key" in result.stdout + result.stderr
