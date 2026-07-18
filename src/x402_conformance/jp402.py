"""Structural validation for the community jp402 / x-jp402 JP-rail extension.

The Japanese qualified-invoice metadata is split across **two surfaces** (confirmed
against real production fixtures, 2026-06-29 — facilitator ``yen402.com`` / the
``x402-jpyc`` reference server; see ``docs/jp402-extension-placement-2026-06-29.md``
and ``tests/fixtures/jp402/``):

  * the **live 402** carries ``jp402`` (no ``x-`` prefix) on each ``accepts[]``
    entry, with a per-quote ``tax`` breakdown (``excl_jpyc`` / ``vat_jpyc`` /
    ``rate``) — *no* registration number; and
  * the **OpenAPI discovery doc** the seller publishes carries ``x-jp402`` (with the
    ``x-`` prefix) at ``info`` (currency) and per-operation, with the ``invoice``
    block (``qualifiedIssuer`` / ``registrationNumber`` / ``smallAmountException``).

So the qualified-invoice ``registrationNumber`` is **not** on the live 402 — the
black-box ``check`` path validates the *tax* breakdown it actually exposes
(:func:`validate_tax`), while an OpenAPI-aware caller validates the *invoice*
(:func:`find_invoice_blocks` + :func:`validate_invoice`).

Reference: https://github.com/kakedashi3/jp402-registry  (community, not x402-core).
"""

from __future__ import annotations

import re
from decimal import Decimal, DecimalException
from typing import Any

#: 適格請求書発行事業者登録番号 — "T" followed by exactly 13 digits.
_T_NUMBER_RE = re.compile(r"^T[0-9]{13}$")

#: The live 402 uses ``jp402``; the OpenAPI doc uses ``x-jp402``. We tolerate either
#: spelling on either surface so a deployment that picks the other one isn't missed.
_JP402_KEYS = ("jp402", "x-jp402")

# Bound attacker-controlled numeric text before later int conversions. uint256
# amounts need at most 78 decimal digits; 1,000 leaves ample extension headroom
# while rejecting exponent/digit bombs that would consume excessive CPU/memory.
_MAX_DECIMAL_DIGITS = 1_000
_MAX_DECIMAL_EXPONENT = 1_000


# --------------------------------------------------------------------------
# Live-402 surface: locate the block and validate the tax breakdown.
# --------------------------------------------------------------------------


def find_jp402_accept(
    raw: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """Find the first ``accepts[]`` entry carrying a jp402 block on a live 402.

    Returns ``(accepts_entry, jp402_block)`` so a caller can cross-check the block
    against that entry's ``amount``; ``None`` if no entry advertises it.
    """
    accepts = raw.get("accepts")
    if isinstance(accepts, list):
        for entry in accepts:
            if not isinstance(entry, dict):
                continue
            for key in _JP402_KEYS:
                block = entry.get(key)
                if isinstance(block, dict):
                    return entry, block
    return None


def find_jp402(raw: dict[str, Any]) -> dict[str, Any] | None:
    """Locate a jp402 block on a live 402 — top-level ``extensions`` or any
    ``accepts[]`` entry. Returns the first block found, else ``None``."""
    extensions = raw.get("extensions")
    if isinstance(extensions, dict):
        for key in _JP402_KEYS:
            block = extensions.get(key)
            if isinstance(block, dict):
                return block
    found = find_jp402_accept(raw)
    return found[1] if found else None


def _to_decimal(v: Any) -> Decimal | None:
    """Parse an int/float/numeric-string into a Decimal; None if not a number.
    Booleans are rejected (``True`` is not a tax amount)."""
    if isinstance(v, bool):
        return None
    try:
        if isinstance(v, int):
            parsed = Decimal(v)
        elif isinstance(v, float):
            parsed = Decimal(str(v))
        elif isinstance(v, str):
            parsed = Decimal(v)
        else:
            return None
    except (DecimalException, ValueError):
        return None
    if not parsed.is_finite():
        return None
    parts = parsed.as_tuple()
    if len(parts.digits) > _MAX_DECIMAL_DIGITS:
        return None
    if abs(parsed.adjusted()) > _MAX_DECIMAL_EXPONENT and not parsed.is_zero():
        return None
    return parsed


def _is_power_of_ten(n: int) -> bool:
    """True iff ``n`` is 10**k for some integer k >= 0 (1, 10, 100, …)."""
    if n < 1:
        return False
    while n % 10 == 0:
        n //= 10
    return n == 1


def validate_tax(tax: dict[str, Any], amount: Any = None) -> list[str]:
    """Structural + arithmetic problems in a live-402 ``jp402.tax`` block.

    Empty list = valid. Checks, all soft-failing (MINOR via RS-PR-015):

    * ``excl_jpyc`` / ``vat_jpyc`` parse as non-negative numbers, ``rate`` as a
      number in ``(0, 1]``;
    * the VAT relation ``vat_jpyc == excl_jpyc * rate`` holds (±1 minor unit of
      rounding); and
    * when ``amount`` is given *and* the breakdown is in whole tokens, the total
      ``excl + vat`` scales onto the atomic ``amount`` by a power of ten
      (``amount == (excl + vat) * 10**k``). This is decimals-agnostic on purpose:
      the observed deployment uses whole-JPYC tax fields against an 18-dp atomic
      ``amount`` (10 + 1 vs 11e18), and ``k == 0`` also covers an atomic-units
      breakdown. The cross-check is skipped for fractional breakdowns so an
      unusual-but-valid quote is never false-flagged.
    """
    problems: list[str] = []
    excl = _to_decimal(tax.get("excl_jpyc"))
    vat = _to_decimal(tax.get("vat_jpyc"))
    rate = _to_decimal(tax.get("rate"))

    if excl is None or excl < 0:
        problems.append(f"excl_jpyc {tax.get('excl_jpyc')!r} is not a non-negative number")
    if vat is None or vat < 0:
        problems.append(f"vat_jpyc {tax.get('vat_jpyc')!r} is not a non-negative number")
    if rate is None or not (Decimal(0) < rate <= Decimal(1)):
        problems.append(f"rate {tax.get('rate')!r} is not a number in (0, 1]")

    if excl is not None and vat is not None and rate is not None and excl >= 0 and vat >= 0:
        expected_vat = excl * rate
        if abs(vat - expected_vat) > 1:
            problems.append(
                f"vat_jpyc {vat} does not match excl_jpyc {excl} * rate {rate} (= {expected_vat})"
            )
        amt = _to_decimal(amount) if amount is not None else None
        total = excl + vat
        if (
            amt is not None
            and total > 0
            and excl == excl.to_integral_value()
            and vat == vat.to_integral_value()
            and amt == amt.to_integral_value()
        ):
            amt_i, total_i = int(amt), int(total)
            if amt_i % total_i != 0 or not _is_power_of_ten(amt_i // total_i):
                problems.append(
                    f"excl_jpyc + vat_jpyc ({total_i}) does not scale to amount ({amt_i}) "
                    "by a power of ten"
                )
    return problems


# --------------------------------------------------------------------------
# Discovery (OpenAPI) surface: locate and validate the invoice block.
# --------------------------------------------------------------------------


def find_invoice_blocks(openapi: dict[str, Any]) -> list[dict[str, Any]]:
    """Collect every ``x-jp402.invoice`` block in a published OpenAPI doc.

    The invoice metadata lives at ``info.x-jp402.invoice`` and/or per-operation
    (``paths.<path>.<method>.x-jp402.invoice``) — *not* on the live 402. Returns
    the invoice dicts found, in document order.
    """
    out: list[dict[str, Any]] = []

    def _invoice(container: Any) -> None:
        if isinstance(container, dict):
            blk = container.get("x-jp402")
            if isinstance(blk, dict) and isinstance(blk.get("invoice"), dict):
                out.append(blk["invoice"])

    _invoice(openapi.get("info"))
    paths = openapi.get("paths")
    if isinstance(paths, dict):
        for path_item in paths.values():
            if isinstance(path_item, dict):
                for op in path_item.values():
                    _invoice(op)
    return out


def validate_invoice(invoice: dict[str, Any]) -> list[str]:
    """Structural problems in an ``x-jp402.invoice`` block (empty list = valid).

    Soft schema: every field is optional, but a *present* field must be well-formed —
    the qualified-invoice registration number must be ``T`` + 13 digits, and the
    boolean flags must be booleans.
    """
    problems: list[str] = []
    reg = invoice.get("registrationNumber")
    if reg is not None and (not isinstance(reg, str) or not _T_NUMBER_RE.match(reg)):
        problems.append(
            f"registrationNumber {reg!r} is not a valid qualified-invoice number "
            "(expected 'T' + 13 digits)"
        )
    for flag in ("qualifiedIssuer", "smallAmountException"):
        if flag in invoice and not isinstance(invoice[flag], bool):
            problems.append(f"{flag} must be a boolean")
    return problems
