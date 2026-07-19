"""SVM ``exact`` payload builder — structural offline verification.

Builds a partially-signed transaction and decodes it back to assert the reference
structure (instruction order, TransferChecked outcome, ATAs, partial signatures)
without any RPC or validator. Additive; skips without the [svm] extra.
"""

from __future__ import annotations

import base64

import pytest

pytest.importorskip("solders")

from solders.hash import Hash
from solders.keypair import Keypair
from solders.signature import Signature
from solders.transaction import VersionedTransaction

from x402_conformance.svm import (
    MEMO_PROGRAM,
    TOKEN_PROGRAM,
    build_exact_svm_transaction,
    derive_ata,
    encode_transfer_checked,
)

USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"

_PAYER = Keypair.from_seed(bytes(range(0, 32)))
_FEE_PAYER = Keypair.from_seed(bytes(range(1, 33))).pubkey()
_MERCHANT = Keypair.from_seed(bytes(range(2, 34))).pubkey()


def _build(**over: object) -> str:
    args: dict[str, object] = {
        "payer_keypair_bytes": bytes(_PAYER),
        "fee_payer": str(_FEE_PAYER),
        "mint": USDC,
        "decimals": 6,
        "pay_to": str(_MERCHANT),
        "amount": 1000,
        "recent_blockhash": str(Hash.default()),
        "memo": "pi_test_123",
    }
    args.update(over)
    return build_exact_svm_transaction(**args)  # type: ignore[arg-type]


def _decode(b64: str) -> VersionedTransaction:
    return VersionedTransaction.from_bytes(base64.b64decode(b64))


def test_fee_payer_is_message_payer_and_unsigned() -> None:
    tx = _decode(_build())
    keys = [str(k) for k in tx.message.account_keys]
    assert keys[0] == str(_FEE_PAYER)  # sponsor is the message payer (account 0)
    assert len(tx.signatures) == 2
    assert tx.signatures[0] == Signature.default()  # feePayer slot unsigned (filled at /settle)
    assert tx.signatures[1] != Signature.default()  # client (payer) signed


def test_instruction_layout_and_transfer_outcome() -> None:
    tx = _decode(_build())
    keys = [str(k) for k in tx.message.account_keys]
    assert len(tx.message.instructions) == 4  # cu-limit, cu-price, transfer, memo

    transfer = tx.message.instructions[2]
    assert keys[transfer.program_id_index] == TOKEN_PROGRAM
    assert bytes(transfer.data) == encode_transfer_checked(1000, 6)

    src = derive_ata(str(_PAYER.pubkey()), USDC, TOKEN_PROGRAM)
    dst = derive_ata(str(_MERCHANT), USDC, TOKEN_PROGRAM)
    assert src in keys and dst in keys

    memo = tx.message.instructions[3]
    assert keys[memo.program_id_index] == MEMO_PROGRAM
    assert bytes(memo.data) == b"pi_test_123"


def test_no_memo_yields_the_three_instruction_reference_layout() -> None:
    # include_memo=False drops the Memo entirely: exactly the reference client's payload
    # (cu-limit, cu-price, transfer), and portable to facilitators that do not allowlist
    # the Memo program (e.g. the Kora demo). This is the FA-SVM live baseline.
    tx = _decode(_build(include_memo=False))
    keys = [str(k) for k in tx.message.account_keys]
    assert len(tx.message.instructions) == 3
    assert MEMO_PROGRAM not in keys


def test_client_signature_is_valid_for_message() -> None:
    tx = _decode(_build())
    # Re-signing the tx's own 0x80-prefixed message with the payer must reproduce the
    # client signature — proves the partial signature binds to this exact transaction.
    expected = _PAYER.sign_message(bytes([0x80]) + bytes(tx.message))
    assert tx.signatures[1] == expected


def test_random_nonce_memo_when_none() -> None:
    tx = _decode(_build(memo=None))
    keys = [str(k) for k in tx.message.account_keys]
    memo = tx.message.instructions[3]
    assert keys[memo.program_id_index] == MEMO_PROGRAM
    assert len(bytes(memo.data)) == 32  # hexlify(16 random bytes)


def test_memo_too_long_rejected() -> None:
    with pytest.raises(ValueError):
        _build(memo="x" * (256 + 1))
