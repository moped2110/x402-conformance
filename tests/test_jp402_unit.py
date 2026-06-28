"""Offline tests for the x-jp402 invoice structural validator."""

from __future__ import annotations

from x402_conformance.jp402 import find_jp402, validate_invoice


def test_valid_t_number_passes() -> None:
    assert validate_invoice({"registrationNumber": "T1234567890123", "qualifiedIssuer": True}) == []


def test_empty_invoice_is_valid() -> None:
    assert validate_invoice({}) == []  # soft schema: all fields optional


def test_bad_t_number_caught() -> None:
    problems = validate_invoice({"registrationNumber": "T12345"})  # too short
    assert problems and "registrationNumber" in problems[0]


def test_non_t_prefix_caught() -> None:
    assert validate_invoice({"registrationNumber": "1234567890123"})  # missing T


def test_non_boolean_flag_caught() -> None:
    problems = validate_invoice({"qualifiedIssuer": "yes"})
    assert problems and "qualifiedIssuer" in problems[0]


def test_find_jp402_in_extensions() -> None:
    raw = {"extensions": {"x-jp402": {"invoice": {"registrationNumber": "T1234567890123"}}}}
    block = find_jp402(raw)
    assert block is not None and "invoice" in block


def test_find_jp402_in_accepts() -> None:
    raw = {"accepts": [{"scheme": "exact", "x-jp402": {"currency": "JPYC"}}]}
    assert find_jp402(raw) == {"currency": "JPYC"}


def test_find_jp402_absent() -> None:
    assert find_jp402({"extensions": {}, "accepts": [{"scheme": "exact"}]}) is None
