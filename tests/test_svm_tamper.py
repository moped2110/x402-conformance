"""SVM tamper primitives — each builds a tx a conformant facilitator MUST reject.

Offline structural assertions (no validator): confirm each tamper injects exactly the
malformation its spec error code names (SOLANA-PLAN §5). These are the building blocks
for the SVM negative checks. Additive; skips without the [svm] extra.
"""

from __future__ import annotations

import base64

import pytest

pytest.importorskip("solders")

from solders.hash import Hash
from solders.keypair import Keypair
from solders.transaction import VersionedTransaction

from x402_conformance.svm import (
    TOKEN_PROGRAM,
    SvmTamper,
    build_exact_svm_transaction,
    derive_ata,
)

USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
_PAYER = Keypair.from_seed(bytes(range(0, 32)))
_FEE = Keypair.from_seed(bytes(range(1, 33))).pubkey()
_MERCHANT = Keypair.from_seed(bytes(range(2, 34))).pubkey()


def _build(tamper: SvmTamper | None = None, **over: object) -> str:
    args: dict[str, object] = {
        "payer_keypair_bytes": bytes(_PAYER),
        "fee_payer": str(_FEE),
        "mint": USDC,
        "decimals": 6,
        "pay_to": str(_MERCHANT),
        "amount": 1000,
        "recent_blockhash": str(Hash.default()),
        "memo": "pi",
        "tamper": tamper,
    }
    args.update(over)
    return build_exact_svm_transaction(**args)  # type: ignore[arg-type]


def _decode(b64: str) -> VersionedTransaction:
    return VersionedTransaction.from_bytes(base64.b64decode(b64))


def _count_transfer_checked(tx: VersionedTransaction) -> int:
    keys = [str(k) for k in tx.message.account_keys]
    return sum(
        1
        for ix in tx.message.instructions
        if keys[ix.program_id_index] == TOKEN_PROGRAM and bytes(ix.data)[:1] == b"\x0c"
    )


def test_clean_build_has_exactly_one_transfer() -> None:
    tx = _decode(_build())
    assert _count_transfer_checked(tx) == 1
    assert len(tx.message.instructions) == 4


def test_drop_compute_budget_shrinks_layout() -> None:
    tx = _decode(_build(SvmTamper.DROP_COMPUTE_BUDGET))
    assert len(tx.message.instructions) == 2  # outside the Path-1 3..7 window


def test_double_transfer_has_two_matching() -> None:
    tx = _decode(_build(SvmTamper.DOUBLE_TRANSFER))
    assert _count_transfer_checked(tx) == 2  # §1.4 requires exactly one


def test_not_transfer_checked_uses_wrong_discriminator() -> None:
    tx = _decode(_build(SvmTamper.NOT_TRANSFER_CHECKED))
    assert bytes(tx.message.instructions[2].data)[0] == 3  # plain Transfer, not 12
    assert _count_transfer_checked(tx) == 0  # no matching TransferChecked remains


def test_fee_payer_in_accounts_breaks_isolation() -> None:
    tx = _decode(_build(SvmTamper.FEE_PAYER_IN_ACCOUNTS))
    keys = [str(k) for k in tx.message.account_keys]
    transfer = tx.message.instructions[2]
    referenced = [keys[i] for i in transfer.accounts]
    assert str(_FEE) in referenced  # feePayer referenced by an instruction — §2.1.1 breach


def test_wrong_pay_to_omits_the_real_merchant_ata() -> None:
    # Parameter-level tamper (no enum): a different pay_to yields a destination ATA
    # that is not ATA(payTo, mint) — the transfer_to_incorrect_ata case.
    tx = _decode(_build(pay_to=str(Keypair().pubkey())))
    keys = [str(k) for k in tx.message.account_keys]
    assert derive_ata(str(_MERCHANT), USDC, TOKEN_PROGRAM) not in keys
