"""Config-file defaults for the `check` command.

Precedence: an explicit CLI flag beats the config file, which beats the built-in
default. Secrets (--signer-key) are never sourced from config.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

import x402_conformance.cli as cli
from x402_conformance.checks import CheckResult, Severity, Status

runner = CliRunner()


def _ok():
    return [CheckResult("RS-HS-001", "t", Severity.MAJOR, "spec", Status.PASS, "")]


def test_load_config_reads_section(tmp_path: Path) -> None:
    cfg = tmp_path / "c.toml"
    cfg.write_text("[check]\ntimeout = 42.0\nconcurrency = 4\n[other]\nx = 1\n", encoding="utf-8")
    assert cli._load_config(cfg, "check") == {"timeout": 42.0, "concurrency": 4}
    assert cli._load_config(cfg, "missing") == {}


def test_missing_explicit_config_exits_2(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(cli, "run_checks", lambda *a, **k: _ok())
    result = runner.invoke(
        cli.app, ["check", "https://t.example", "--config", str(tmp_path / "nope.toml")]
    )
    assert result.exit_code == 2
    assert "config file not found" in result.output


def test_config_supplies_timeout(monkeypatch, tmp_path: Path) -> None:
    seen: dict[str, object] = {}
    monkeypatch.setattr(cli, "run_checks", lambda url, **k: seen.update(k) or _ok())
    cfg = tmp_path / "c.toml"
    cfg.write_text("[check]\ntimeout = 42.0\n", encoding="utf-8")
    result = runner.invoke(cli.app, ["check", "https://t.example", "--config", str(cfg)])
    assert result.exit_code == 0
    assert seen["timeout"] == 42.0


def test_cli_flag_overrides_config(monkeypatch, tmp_path: Path) -> None:
    seen: dict[str, object] = {}
    monkeypatch.setattr(cli, "run_checks", lambda url, **k: seen.update(k) or _ok())
    cfg = tmp_path / "c.toml"
    cfg.write_text("[check]\ntimeout = 42.0\n", encoding="utf-8")
    result = runner.invoke(
        cli.app, ["check", "https://t.example", "--config", str(cfg), "--timeout", "7"]
    )
    assert result.exit_code == 0
    assert seen["timeout"] == 7.0  # explicit CLI flag wins


def test_config_cannot_enable_active(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(cli, "run_checks", lambda *a, **k: _ok())
    cfg = tmp_path / "c.toml"
    cfg.write_text("[check]\nactive = true\nconcurrency = 4\n", encoding="utf-8")
    result = runner.invoke(cli.app, ["check", "https://t.example", "--config", str(cfg)])
    assert result.exit_code == 2
    assert "cannot be enabled from config" in result.output


def test_string_boolean_is_a_config_error(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(cli, "run_checks", lambda *a, **k: _ok())
    cfg = tmp_path / "c.toml"
    cfg.write_text('[check]\npay = "false"\n', encoding="utf-8")
    result = runner.invoke(cli.app, ["check", "https://t.example", "--config", str(cfg)])
    assert result.exit_code == 2
    assert "pay must be a boolean" in result.output


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("timeout = true", "timeout must be a number"),
        ("timeout = 0", "timeout must be a number"),
        ("concurrency = 0", "concurrency must be an integer"),
        ("rpc_url = 12", "rpc_url must be a string"),
        ("unknown = true", "unknown key"),
    ],
)
def test_config_schema_is_strict(monkeypatch, tmp_path: Path, body: str, message: str) -> None:
    monkeypatch.setattr(cli, "run_checks", lambda *a, **k: _ok())
    cfg = tmp_path / "c.toml"
    cfg.write_text(f"[check]\n{body}\n", encoding="utf-8")
    result = runner.invoke(cli.app, ["check", "https://t.example", "--config", str(cfg)])
    assert result.exit_code == 2
    assert message in result.output
