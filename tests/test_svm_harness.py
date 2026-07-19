"""SVM settlement harness — a valid exact-SVM payment settles in-process (K2-1 step 1).

Proves the LiteSVM harness end to end: a client-signed ``exact`` transaction built by
``svm.build_exact_svm_transaction`` is settled by filling the feePayer slot, executes
the ``TransferChecked`` on the runtime, and moves the merchant's token balance by the
paid amount. This is the Path-1 (standard-wallet) positive path the negative checks
will build on. Additive; skips without the [svm] extra.
"""

from __future__ import annotations

import pytest

pytest.importorskip("solders")

from x402_conformance.svm import build_exact_svm_transaction
from x402_conformance.svm_harness import SvmHarness


def _paid_transaction(harness: SvmHarness, amount: int) -> str:
    return build_exact_svm_transaction(
        payer_keypair_bytes=bytes(harness.payer),
        fee_payer=str(harness.fee_payer.pubkey()),
        mint=str(harness.mint),
        decimals=harness.decimals,
        pay_to=str(harness.merchant.pubkey()),
        amount=amount,
        recent_blockhash=harness.latest_blockhash(),
        memo="pi_harness_1",
        token_program=harness.token_program,
    )


def test_a_valid_exact_payment_settles_and_moves_the_balance() -> None:
    harness = SvmHarness(decimals=6)
    before = harness.token_balance(harness.merchant_ata)

    outcome = harness.settle(_paid_transaction(harness, 1000))

    assert outcome.settled, outcome.error
    assert harness.token_balance(harness.merchant_ata) == before + 1000


def test_the_payer_balance_is_debited_by_the_same_amount() -> None:
    harness = SvmHarness(decimals=6)
    payer_before = harness.token_balance(harness.payer_ata)

    assert harness.settle(_paid_transaction(harness, 2500)).settled
    assert harness.token_balance(harness.payer_ata) == payer_before - 2500
