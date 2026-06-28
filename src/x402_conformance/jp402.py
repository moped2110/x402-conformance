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
envelope and is not covered yet (pending fixture).
"""

from __future__ import annotations

import re
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
