"""Offline tests for the jp402 / x-jp402 JP-rail validators.

Two surfaces (see docs/jp402-extension-placement-2026-06-29.md): the live 402 carries
`jp402.tax` on accepts[]; the OpenAPI doc carries `x-jp402.invoice`. Both are pinned
to the real production fixtures in tests/fixtures/jp402/.
"""

from __future__ import annotations

import json
from pathlib import Path

from x402_conformance.jp402 import (
    find_invoice_blocks,
    find_jp402,
    find_jp402_accept,
    validate_invoice,
    validate_tax,
)

_FIX = Path(__file__).resolve().parent / "fixtures" / "jp402"


def _load(name: str) -> dict:
    return json.loads((_FIX / name).read_text(encoding="utf-8"))


# --- invoice validator (discovery / OpenAPI surface) ---


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


# --- locating the block on either surface ---


def test_find_jp402_in_extensions() -> None:
    raw = {"extensions": {"x-jp402": {"invoice": {"registrationNumber": "T1234567890123"}}}}
    block = find_jp402(raw)
    assert block is not None and "invoice" in block


def test_find_jp402_in_accepts() -> None:
    raw = {"accepts": [{"scheme": "exact", "x-jp402": {"currency": "JPYC"}}]}
    assert find_jp402(raw) == {"currency": "JPYC"}


def test_find_jp402_absent() -> None:
    assert find_jp402({"extensions": {}, "accepts": [{"scheme": "exact"}]}) is None


# --- live-402 fixture: `jp402` (no x-) on accepts[], carrying `tax` ---


def test_find_jp402_accept_on_live_fixture() -> None:
    raw = _load("live-402-envelope.json")
    found = find_jp402_accept(raw)
    assert found is not None
    entry, block = found
    assert "tax" in block and entry.get("amount") == "11000000000000000000"


def test_live_fixture_tax_is_valid() -> None:
    raw = _load("live-402-envelope.json")
    entry, block = find_jp402_accept(raw)  # type: ignore[misc]
    assert validate_tax(block["tax"], entry["amount"]) == []


def test_tax_vat_relation_mismatch_caught() -> None:
    # vat should be excl * rate = 10 * 0.1 = 1; 5 is wrong.
    problems = validate_tax(
        {"excl_jpyc": "10", "vat_jpyc": "5", "rate": 0.1}, "11000000000000000000"
    )
    assert problems and "vat_jpyc" in problems[0]


def test_tax_amount_scaling_mismatch_caught() -> None:
    # excl+vat = 11 must scale to amount by a power of ten; 12e18 does not.
    problems = validate_tax(
        {"excl_jpyc": "10", "vat_jpyc": "1", "rate": 0.1}, "12000000000000000000"
    )
    assert problems and "scale to amount" in problems[0]


def test_tax_atomic_units_also_valid() -> None:
    # k == 0: a breakdown already in atomic units (excl+vat == amount) passes too.
    assert validate_tax({"excl_jpyc": "10", "vat_jpyc": "1", "rate": 0.1}, "11") == []


def test_tax_bad_rate_caught() -> None:
    problems = validate_tax({"excl_jpyc": "10", "vat_jpyc": "1", "rate": 5})
    assert problems and "rate" in problems[0]


def test_tax_without_amount_skips_scaling() -> None:
    # No amount → only structural + vat relation, no scaling cross-check.
    assert validate_tax({"excl_jpyc": "10", "vat_jpyc": "1", "rate": 0.1}) == []


# --- discovery fixture: `x-jp402.invoice` in the OpenAPI doc ---


def test_find_and_validate_invoice_on_openapi_fixture() -> None:
    doc = _load("openapi-discovery-x-jp402.json")
    invoices = find_invoice_blocks(doc)
    assert len(invoices) == 1
    assert invoices[0]["registrationNumber"] == "T0000000000000"
    assert validate_invoice(invoices[0]) == []
