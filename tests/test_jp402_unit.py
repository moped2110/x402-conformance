"""Offline tests for the x-jp402 invoice structural validator."""

from __future__ import annotations

from x402_conformance.jp402 import (
    find_jp402,
    find_jp402_tax,
    validate_invoice,
    validate_tax,
)


def test_valid_t_number_passes() -> None:
    assert (
        validate_invoice(
            {"registrationNumber": "T1234567890123", "qualifiedIssuer": True}
        )
        == []
    )


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
    raw = {
        "extensions": {"x-jp402": {"invoice": {"registrationNumber": "T1234567890123"}}}
    }
    block = find_jp402(raw)
    assert block is not None and "invoice" in block


def test_find_jp402_in_accepts() -> None:
    raw = {"accepts": [{"scheme": "exact", "x-jp402": {"currency": "JPYC"}}]}
    assert find_jp402(raw) == {"currency": "JPYC"}


def test_find_jp402_absent() -> None:
    assert find_jp402({"extensions": {}, "accepts": [{"scheme": "exact"}]}) is None


# --- jp402.tax (per-quote consumption-tax breakdown on the live 402) ---


def test_valid_tax_passes() -> None:
    # 10 excl + 1 vat at 10% — matches the x402-jpyc reference fixture.
    assert validate_tax({"excl_jpyc": "10", "vat_jpyc": "1", "rate": 0.1}) == []


def test_zero_rate_zero_vat_is_valid() -> None:
    assert validate_tax({"excl_jpyc": "10", "vat_jpyc": "0", "rate": 0}) == []


def test_rounded_vat_is_tolerated() -> None:
    # 105 * 0.08 = 8.4, which rounds to vat_jpyc "8" at its own (integer) precision.
    assert validate_tax({"excl_jpyc": "105", "vat_jpyc": "8", "rate": 0.08}) == []


def test_inconsistent_vat_caught() -> None:
    problems = validate_tax({"excl_jpyc": "10", "vat_jpyc": "5", "rate": 0.1})
    assert problems and "vat_jpyc" in problems[0]


def test_rate_out_of_range_caught() -> None:
    assert validate_tax({"excl_jpyc": "10", "vat_jpyc": "1", "rate": 1.5})
    assert validate_tax({"excl_jpyc": "10", "vat_jpyc": "1", "rate": -0.1})


def test_non_numeric_excl_caught() -> None:
    problems = validate_tax({"excl_jpyc": "abc", "vat_jpyc": "1", "rate": 0.1})
    assert problems and "excl_jpyc" in problems[0]


def test_non_string_amounts_caught() -> None:
    # On-wire amounts are decimal strings, not bare numbers.
    assert validate_tax({"excl_jpyc": 10, "vat_jpyc": 1, "rate": 0.1})


def test_amount_tie_consistent_when_decimals_supplied() -> None:
    # Major-unit tax (10 + 1 = 11) ties to atomic amount only once decimals is known.
    assert (
        validate_tax(
            {"excl_jpyc": "10", "vat_jpyc": "1", "rate": 0.1},
            amount="11000000000000000000",
            decimals=18,
        )
        == []
    )


def test_amount_tie_mismatch_caught() -> None:
    problems = validate_tax(
        {"excl_jpyc": "10", "vat_jpyc": "1", "rate": 0.1},
        amount="99000000000000000000",
        decimals=18,
    )
    assert problems and "amount" in problems[0]


def test_find_jp402_tax_on_accepts() -> None:
    raw = {
        "accepts": [
            {
                "scheme": "exact",
                "jp402": {"tax": {"excl_jpyc": "10", "vat_jpyc": "1", "rate": 0.1}},
            }
        ]
    }
    assert find_jp402_tax(raw) == {"excl_jpyc": "10", "vat_jpyc": "1", "rate": 0.1}


def test_find_jp402_tax_absent() -> None:
    assert find_jp402_tax({"accepts": [{"scheme": "exact"}]}) is None
    # x-jp402 (invoice) on accepts is NOT a jp402.tax block.
    assert (
        find_jp402_tax(
            {"accepts": [{"scheme": "exact", "x-jp402": {"currency": "JPYC"}}]}
        )
        is None
    )
