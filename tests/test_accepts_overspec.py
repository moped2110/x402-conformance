"""RS-PR-017..020: accepts-overspecification checks.

These are passive, spec-precise inspections of the `accepts[]` array:
  * RS-PR-017 (MAJOR) — the `scheme` value is one the protocol names.
  * RS-PR-018 (MAJOR) — no two entries contradict each other on the same rail+asset.
  * RS-PR-019 (MINOR) — `extra` fields belong to the entry's declared scheme.
  * RS-PR-020 (MINOR) — no entry carries fields outside the v2 PaymentRequirements set.

The two MAJOR checks gate the verdict; the two MINOR checks warn without gating.
"""

from __future__ import annotations

import copy
from typing import Any

from conftest import TARGET_URL, transport_with_402
from test_handshake import by_id

from x402_conformance.checks import Status
from x402_conformance.report import exit_code
from x402_conformance.runner import run_checks


def _run(payload: dict[str, Any]) -> list:
    """Run the passive registry against a mock 402 carrying `payload`."""
    return run_checks(TARGET_URL, transport=transport_with_402(payload))


# --- RS-PR-017: known scheme ------------------------------------------------


def test_known_scheme_passes(valid_payload: dict) -> None:
    """The spec example advertises `exact`, a known scheme."""
    assert by_id(_run(valid_payload), "RS-PR-017").status == Status.PASS


def test_unknown_scheme_fails_and_gates(valid_payload: dict) -> None:
    """An invented scheme is unpayable — MAJOR FAIL that gates the verdict."""
    valid_payload["accepts"][0]["scheme"] = "premium"
    results = _run(valid_payload)
    r = by_id(results, "RS-PR-017")
    assert r.status == Status.FAIL
    assert "premium" in r.detail
    assert exit_code(results) == 1  # MAJOR gates


def test_upto_scheme_is_known(valid_payload: dict) -> None:
    """`upto` is a protocol-named scheme, so the scheme check passes."""
    valid_payload["accepts"][0]["scheme"] = "upto"
    assert by_id(_run(valid_payload), "RS-PR-017").status == Status.PASS


def test_no_accepts_entries_skips(valid_payload: dict) -> None:
    """With an empty accepts array there is nothing to classify — SKIP."""
    valid_payload["accepts"] = []
    assert by_id(_run(valid_payload), "RS-PR-017").status == Status.SKIP


# --- RS-PR-018: contradictory entries ---------------------------------------


def test_single_entry_has_no_contradiction(valid_payload: dict) -> None:
    """One entry cannot contradict itself."""
    assert by_id(_run(valid_payload), "RS-PR-018").status == Status.PASS


def test_same_rail_asset_different_payto_fails_and_gates(valid_payload: dict) -> None:
    """Same scheme+network+asset at two payTo addresses is ambiguous — MAJOR FAIL."""
    second = copy.deepcopy(valid_payload["accepts"][0])
    second["payTo"] = "0x000000000000000000000000000000000000dead"
    valid_payload["accepts"].append(second)
    results = _run(valid_payload)
    assert by_id(results, "RS-PR-018").status == Status.FAIL
    assert exit_code(results) == 1  # MAJOR gates


def test_same_rail_different_asset_is_a_legit_choice(valid_payload: dict) -> None:
    """Offering the same rail in two assets (USDC or DAI) is a choice, not a contradiction."""
    second = copy.deepcopy(valid_payload["accepts"][0])
    second["asset"] = "0x6B175474E89094C44Da98b954EedeAC495271d0F"  # DAI
    valid_payload["accepts"].append(second)
    assert by_id(_run(valid_payload), "RS-PR-018").status == Status.PASS


def test_byte_identical_duplicate_is_not_a_contradiction(valid_payload: dict) -> None:
    """Two identical entries collapse to one variant — redundant, not contradictory."""
    valid_payload["accepts"].append(copy.deepcopy(valid_payload["accepts"][0]))
    assert by_id(_run(valid_payload), "RS-PR-018").status == Status.PASS


# --- RS-PR-019: extra matches scheme ----------------------------------------


def test_exact_domain_extra_passes(valid_payload: dict) -> None:
    """`exact` carrying only name/version (the EIP-712 domain) is correct."""
    assert by_id(_run(valid_payload), "RS-PR-019").status == Status.PASS


def test_exact_with_upto_extra_warns_without_gating(valid_payload: dict) -> None:
    """An `exact` entry carrying an upto-only channel field is a mismatch — MINOR, non-gating."""
    valid_payload["accepts"][0]["extra"]["feePayer"] = "0xfee"
    results = _run(valid_payload)
    r = by_id(results, "RS-PR-019")
    assert r.status == Status.FAIL
    assert "feePayer" in r.detail
    assert exit_code(results) == 0  # MINOR does not gate


def test_upto_with_asset_transfer_method_warns(valid_payload: dict) -> None:
    """`upto` has no assetTransferMethod discriminator; carrying it is a mismatch."""
    valid_payload["accepts"][0].update(
        scheme="upto",
        network="solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
        payTo="9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",
        extra={"assetTransferMethod": "eip3009"},
    )
    assert by_id(_run(valid_payload), "RS-PR-019").status == Status.FAIL


def test_extra_vs_scheme_skips_on_v1() -> None:
    """The extra vocabularies are v2 scheme-spec; a v1 envelope skips this check."""
    v1 = {
        "x402Version": 1,
        "accepts": [{"scheme": "exact", "network": "eip155:137", "extra": {"feePayer": "x"}}],
    }
    assert by_id(_run(v1), "RS-PR-019").status == Status.SKIP


# --- RS-PR-020: no fields outside the v2 schema -----------------------------


def test_clean_entry_has_no_extra_fields(valid_payload: dict) -> None:
    """The spec example carries only the v2 PaymentRequirements fields."""
    assert by_id(_run(valid_payload), "RS-PR-020").status == Status.PASS


def test_non_v2_field_warns_without_gating(valid_payload: dict) -> None:
    """A field outside §5.1.2 (here legacy `outputSchema`) is flagged — MINOR, non-gating."""
    valid_payload["accepts"][0]["outputSchema"] = {}
    results = _run(valid_payload)
    r = by_id(results, "RS-PR-020")
    assert r.status == Status.FAIL
    assert "outputSchema" in r.detail
    assert exit_code(results) == 0  # MINOR does not gate


def test_unknown_field_skips_on_v1() -> None:
    """The v2 field vocabulary does not apply to a v1 envelope — SKIP."""
    v1 = {
        "x402Version": 1,
        "accepts": [{"scheme": "exact", "network": "eip155:137", "somethingElse": 1}],
    }
    assert by_id(_run(v1), "RS-PR-020").status == Status.SKIP
