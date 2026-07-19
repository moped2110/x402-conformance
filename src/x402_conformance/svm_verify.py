"""Structural verification of an exact-SVM transaction (Path 1) against the spec MUSTs.

The SVM ``exact`` scheme verifies by *outcome and structure*, not a single signature:
a conformant facilitator must reject a payload that does not carry exactly one
``TransferChecked`` of at least ``amount`` to the ATA derived from ``payTo``+``asset``,
in a standard 3–7 instruction layout, without the feePayer wired into the transfer.

``verify_exact_svm_transaction`` implements those Path-1 structural MUSTs and returns
the spec error code (``SPEC_ERROR_REASONS``) for the first violation, or None when the
payload is well-formed. Each ``SvmTamper`` maps to exactly one of these codes (see
SOLANA-PLAN §5), so the negative checks fall out of the builder mechanically. Pure
decode + structural analysis; needs ``solders`` (the ``[svm]`` extra), no runtime.
"""

from __future__ import annotations

import base64

from .svm import IX_TRANSFER_CHECKED, TOKEN_PROGRAMS, derive_ata

# Spec error codes (subset of SPEC_ERROR_REASONS) this Path-1 verifier can raise.
ERR_INSTRUCTIONS_LENGTH = "invalid_exact_svm_payload_transaction_instructions_length"
ERR_NOT_TRANSFER_CHECKED = (
    "invalid_exact_svm_payload_transaction_instruction_not_spl_token_transfer_checked"
)
ERR_EXACTLY_ONE = "invalid_exact_svm_payload_transaction_instructions"
ERR_INCORRECT_ATA = "invalid_exact_svm_payload_transaction_transfer_to_incorrect_ata"
ERR_AMOUNT_MISMATCH = "invalid_exact_svm_payload_transaction_amount_mismatch"
ERR_FEE_PAYER_IN_ACCOUNTS = (
    "invalid_exact_svm_payload_transaction_fee_payer_included_in_instruction_accounts"
)

_PATH1_MIN_INSTRUCTIONS = 3
_PATH1_MAX_INSTRUCTIONS = 7


def verify_exact_svm_transaction(
    b64_transaction: str,
    *,
    mint: str,
    pay_to: str,
    amount: int,
    fee_payer: str,
    token_program: str = "",
) -> str | None:
    """Return the spec error code for the first Path-1 violation, or None if valid.

    ``token_program`` defaults to the SPL Token program via the ATA derivation; pass
    the Token-2022 program to check a Token-2022 payment.
    """
    from solders.transaction import VersionedTransaction

    from .svm import TOKEN_PROGRAM

    program = token_program or TOKEN_PROGRAM
    tx = VersionedTransaction.from_bytes(base64.b64decode(b64_transaction))
    message = tx.message
    keys = [str(k) for k in message.account_keys]
    instructions = list(message.instructions)

    if not _PATH1_MIN_INSTRUCTIONS <= len(instructions) <= _PATH1_MAX_INSTRUCTIONS:
        return ERR_INSTRUCTIONS_LENGTH

    token_ix = [ix for ix in instructions if keys[ix.program_id_index] in TOKEN_PROGRAMS]
    transfers = [ix for ix in token_ix if bytes(ix.data)[:1] == bytes([IX_TRANSFER_CHECKED])]
    if not transfers:
        # A token instruction that is not TransferChecked, or no token transfer at all.
        return ERR_NOT_TRANSFER_CHECKED

    expected_dest = derive_ata(pay_to, mint, program)
    matching = [ix for ix in transfers if keys[ix.accounts[2]] == expected_dest]
    if len(matching) > 1:
        # §1.4: exactly one matching transfer. A second one (double settle) is invalid.
        return ERR_EXACTLY_ONE
    if not matching:
        return ERR_INCORRECT_ATA

    transfer = matching[0]
    paid = int.from_bytes(bytes(transfer.data)[1:9], "little")
    if paid < amount:
        return ERR_AMOUNT_MISMATCH

    # §2.1.1 fee-payer isolation: the sponsor must never be wired into the transfer.
    if fee_payer in {keys[i] for i in transfer.accounts}:
        return ERR_FEE_PAYER_IN_ACCOUNTS

    return None
