"""Tests for the explicitly opt-in PQC-001..006 profile."""

from __future__ import annotations

import copy

from typer.testing import CliRunner

from pqc_fixture_sut import PQCFixtureSUT
from x402_conformance.checks.base import Status
from x402_conformance.cli import app
from x402_conformance.pqc_runner import run_pqc_checks

from conftest import TARGET_URL, valid_transport


def _by_id(results: list[object], check_id: str) -> object:
    return next(result for result in results if getattr(result, "check_id") == check_id)


def test_fixture_sut_passes_all_six_pqc_checks() -> None:
    results = run_pqc_checks(TARGET_URL, transport=PQCFixtureSUT().transport())
    assert [result.check_id for result in results] == [f"PQC-{n:03}" for n in range(1, 7)]
    assert all(result.status == Status.PASS for result in results)


def test_pqc_profile_is_default_off(valid_transport: object) -> None:
    from x402_conformance.runner import run_checks

    results = run_checks(TARGET_URL, transport=valid_transport)
    assert not any(result.check_id.startswith("PQC-") for result in results)


def test_pqc_001_rejects_invalid_capability_schema() -> None:
    sut = PQCFixtureSUT()
    sut.capability["extensions"]["pqc"]["algorithms"] = ["ML-DSA-65"]
    results = run_pqc_checks(TARGET_URL, transport=sut.transport())
    assert _by_id(results, "PQC-001").status == Status.FAIL


def test_pqc_002_rejects_wrong_algorithm_and_signature_length() -> None:
    sut = PQCFixtureSUT()
    sut.receipt["sig_v2"]["pqc"]["alg"] = "ML-DSA-44"
    sut.receipt["sig_v2"]["pqc"]["signature"] = "AA"
    results = run_pqc_checks(TARGET_URL, transport=sut.transport())
    assert _by_id(results, "PQC-002").status == Status.FAIL


def test_pqc_003_requires_both_valid_signatures() -> None:
    sut = PQCFixtureSUT()
    sut.receipt["sig_v2"]["classical"]["signature"] = "AA"
    results = run_pqc_checks(TARGET_URL, transport=sut.transport())
    assert _by_id(results, "PQC-003").status == Status.FAIL


def test_pqc_004_catches_sut_that_ignores_tampered_mldsa() -> None:
    results = run_pqc_checks(TARGET_URL, transport=PQCFixtureSUT(ignore_pqc=True).transport())
    assert _by_id(results, "PQC-004").status == Status.FAIL


def test_pqc_005_accepts_explicit_degraded_downgrade() -> None:
    results = run_pqc_checks(TARGET_URL, transport=PQCFixtureSUT(allow_downgrade=True).transport())
    assert _by_id(results, "PQC-005").status == Status.PASS


def test_pqc_005_rejects_silent_downgrade() -> None:
    sut = PQCFixtureSUT(allow_downgrade=True)
    original_transport = sut.transport()
    results = run_pqc_checks(TARGET_URL, transport=original_transport)
    assert "degraded" in _by_id(results, "PQC-005").detail


def test_pqc_006_detects_unsigned_algorithm_metadata() -> None:
    sut = PQCFixtureSUT()
    original = copy.deepcopy(sut.receipt)
    sut.receipt["sig_v2"]["pqc"]["alg"] = "ML-DSA-44"
    sut.receipt["sig_v2"]["pqc"]["signature"] = original["sig_v2"]["pqc"]["signature"]
    results = run_pqc_checks(TARGET_URL, transport=sut.transport())
    assert _by_id(results, "PQC-006").status == Status.FAIL


def test_cli_profile_pqc_is_explicit(monkeypatch: object) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["check", TARGET_URL, "--profile", "unknown", "--no-log"])
    assert result.exit_code == 2
    assert "pqc" in result.output
