"""Structural validation for the community ``x-jp402`` invoice extension.

``x-jp402`` is a **non-official, JP-rail community extension** (jp402-registry) that
carries Japanese qualified-invoice metadata alongside an x402 service. It is
deliberately isolated so a generic crawler ignores it and only JP-aware tooling
reads it. This module structurally validates the ``invoice`` block — primarily the
qualified-invoice issuer registration number (適格請求書発行事業者登録番号), which
must be the National Tax Agency's ``T`` + 13-digit form.

Reference: https://github.com/kakedashi3/jp402-registry  (community, not x402-core).

Note: the canonical home of ``x-jp402`` is the discovery catalog
(``.well-known/x402-catalog.json``). Its placement on a *live* 402 response is
provisional here — confirm against a real fixture. The separate per-quote
``jp402.tax`` breakdown (``excl_jpyc`` / ``vat_jpyc`` / ``rate``) lives on the 402
envelope and is validated separately by ``validate_tax`` / ``find_jp402_tax``.
"""

from __future__ import annotations

import re
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any

#: 適格請求書発行事業者登録番号 — "T" followed by exactly 13 digits.
_T_NUMBER_RE = re.compile(r"^T[0-9]{13}$")


def find_jp402(raw: dict[str, Any]) -> dict[str, Any] | None:
    """Locate an ``x-jp402`` block in a decoded PaymentRequired payload, if present.

    Looks in the top-level ``extensions`` (``x-jp402`` / ``jp402``) and on each
    ``accepts`` entry. Returns the first ``x-jp402`` object found, else ``None``.
    Placement on the live 402 is provisional — confirm against a real fixture.
    """
    extensions = raw.get("extensions")
    if isinstance(extensions, dict):
        for key in ("x-jp402", "jp402"):
            block = extensions.get(key)
            if isinstance(block, dict):
                return block
    accepts = raw.get("accepts")
    if isinstance(accepts, list):
        for entry in accepts:
            if isinstance(entry, dict):
                block = entry.get("x-jp402")
                if isinstance(block, dict):
                    return block
    return None


def validate_invoice(invoice: dict[str, Any]) -> list[str]:
    """Structural problems in an ``x-jp402.invoice`` block (empty list = valid).

    Soft schema: every field is optional, but a *present* field must be well-formed.
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


def find_jp402_tax(raw: dict[str, Any]) -> dict[str, Any] | None:
    """Locate a per-quote ``jp402.tax`` block on a decoded PaymentRequired payload.

    On the live 402, the JP tax breakdown rides each ``accepts`` entry under
    ``jp402`` (no ``x-`` prefix) — distinct from the ``x-jp402.invoice`` metadata,
    which lives in the OpenAPI/catalog discovery doc (see ``find_jp402`` and the
    ``tests/fixtures/jp402`` golden files). Returns the first ``tax`` object found,
    else ``None``.
    """
    accepts = raw.get("accepts")
    if isinstance(accepts, list):
        for entry in accepts:
            if isinstance(entry, dict):
                jp402 = entry.get("jp402")
                if isinstance(jp402, dict):
                    tax = jp402.get("tax")
                    if isinstance(tax, dict):
                        return tax
    return None


def _nonneg_decimal(value: Any) -> Decimal | None:
    """Parse a non-negative decimal *string* (the on-wire form), else ``None``."""
    if not isinstance(value, str):
        return None
    try:
        parsed = Decimal(value)
    except InvalidOperation:
        return None
    return parsed if parsed >= 0 else None


def validate_tax(
    tax: dict[str, Any],
    *,
    amount: str | None = None,
    decimals: int | None = None,
) -> list[str]:
    """Structural problems in a ``jp402.tax`` block (empty list = valid).

    Validates the per-quote consumption-tax breakdown carried on the live 402:
    ``excl_jpyc`` (tax-exclusive base) / ``vat_jpyc`` (tax amount) / ``rate``.
    Checks, all version-agnostic and decimals-free:

    * ``excl_jpyc`` / ``vat_jpyc`` are non-negative decimal strings;
    * ``rate`` is a number in ``0..1``;
    * internal consistency: ``vat_jpyc == excl_jpyc * rate`` rounded to ``vat_jpyc``'s
      own precision (catches a mis-stated tax line; tolerant of normal rounding).

    The total tie ``excl_jpyc + vat_jpyc == amount`` that #2386's discussion mentioned
    needs care: on real JPYC endpoints the tax fields are in *major* units (e.g.
    ``"10"`` / ``"1"``) while ``amount`` is *atomic* (e.g. ``11000000000000000000``),
    so the two only reconcile once token ``decimals`` is known — which the bare 402
    does not carry. Pass ``amount`` + ``decimals`` to opt into that tie; omit them to
    keep the check black-box.
    """
    problems: list[str] = []
    excl = _nonneg_decimal(tax.get("excl_jpyc"))
    vat = _nonneg_decimal(tax.get("vat_jpyc"))
    rate = tax.get("rate")

    if excl is None:
        problems.append("excl_jpyc must be a non-negative decimal string")
    if vat is None:
        problems.append("vat_jpyc must be a non-negative decimal string")

    rate_num: float | None = None
    if not isinstance(rate, (int, float)) or isinstance(rate, bool):
        problems.append("rate must be a number")
    elif not 0 <= rate <= 1:
        problems.append(f"rate {rate} is out of range (expected 0..1)")
    else:
        rate_num = rate

    if excl is not None and vat is not None and rate_num is not None:
        expected = excl * Decimal(str(rate_num))
        exponent = vat.as_tuple().exponent
        places = -exponent if isinstance(exponent, int) and exponent < 0 else 0
        expected_rounded = expected.quantize(
            Decimal(1).scaleb(-places), rounding=ROUND_HALF_UP
        )
        if expected_rounded != vat:
            problems.append(
                f"vat_jpyc {tax.get('vat_jpyc')!r} is inconsistent with "
                f"excl_jpyc * rate (≈ {expected_rounded})"
            )

    if (
        amount is not None
        and decimals is not None
        and excl is not None
        and vat is not None
    ):
        try:
            expected_atomic = (excl + vat) * (Decimal(10) ** decimals)
            if expected_atomic != Decimal(amount):
                problems.append(
                    f"excl_jpyc + vat_jpyc ({excl + vat}) does not equal amount "
                    f"{amount!r} at {decimals} decimals"
                )
        except (InvalidOperation, TypeError):
            problems.append(f"amount {amount!r} is not a valid atomic integer string")

    return problems
