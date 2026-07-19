"""Structural exact-SVM verification maps each tamper to its spec error code (K2-1 step 2).

The builder's ``SvmTamper`` variants and two plain wrong-input cases (short amount,
wrong destination ATA) must each produce exactly the SOLANA-PLAN §5 error the spec
assigns, while a clean payload verifies. Offline decode; skips without the [svm] extra.
"""

from __future__ import annotations

import pytest

pytest.importorskip("solders")

from solders.hash import Hash
from solders.keypair import Keypair

from x402_conformance.svm import SvmTamper, build_exact_svm_transaction
from x402_conformance.svm_verify import (
    ERR_AMOUNT_MISMATCH,
    ERR_EXACTLY_ONE,
    ERR_FEE_PAYER_IN_ACCOUNTS,
    ERR_INCORRECT_ATA,
    ERR_INSTRUCTIONS_LENGTH,
    ERR_NOT_TRANSFER_CHECKED,
    verify_exact_svm_transaction,
)

USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
_PAYER = Keypair.from_seed(bytes(range(0, 32)))
_FEE_PAYER = Keypair.from_seed(bytes(range(1, 33))).pubkey()
_MERCHANT = Keypair.from_seed(bytes(range(2, 34))).pubkey()
_OTHER = Keypair.from_seed(bytes(range(3, 35))).pubkey()


def _build(*, amount: int = 1000, pay_to=None, tamper: SvmTamper | None = None) -> str:
    return build_exact_svm_transaction(
        payer_keypair_bytes=bytes(_PAYER),
        fee_payer=str(_FEE_PAYER),
        mint=USDC,
        decimals=6,
        pay_to=str(pay_to or _MERCHANT),
        amount=amount,
        recent_blockhash=str(Hash.default()),
        memo="pi_verify_1",
        tamper=tamper,
    )


def _verify(b64: str, *, amount: int = 1000) -> str | None:
    return verify_exact_svm_transaction(
        b64, mint=USDC, pay_to=str(_MERCHANT), amount=amount, fee_payer=str(_FEE_PAYER)
    )


def test_a_clean_payload_verifies() -> None:
    assert _verify(_build()) is None


def test_dropped_compute_budget_is_wrong_instruction_count() -> None:
    assert _verify(_build(tamper=SvmTamper.DROP_COMPUTE_BUDGET)) == ERR_INSTRUCTIONS_LENGTH


def test_plain_transfer_is_not_transfer_checked() -> None:
    assert _verify(_build(tamper=SvmTamper.NOT_TRANSFER_CHECKED)) == ERR_NOT_TRANSFER_CHECKED


def test_double_transfer_breaks_exactly_one() -> None:
    assert _verify(_build(tamper=SvmTamper.DOUBLE_TRANSFER)) == ERR_EXACTLY_ONE


def test_fee_payer_in_transfer_accounts_is_rejected() -> None:
    assert _verify(_build(tamper=SvmTamper.FEE_PAYER_IN_ACCOUNTS)) == ERR_FEE_PAYER_IN_ACCOUNTS


def test_amount_below_required_is_a_mismatch() -> None:
    # The transaction pays 500 but the resource requires 1000.
    assert _verify(_build(amount=500), amount=1000) == ERR_AMOUNT_MISMATCH


def test_transfer_to_the_wrong_ata_is_rejected() -> None:
    # Paid to a different merchant's ATA than the one payTo derives.
    assert _verify(_build(pay_to=_OTHER)) == ERR_INCORRECT_ATA
