"""Solana / SVM foundations for the ``exact`` scheme.

Purely additive: no EVM path imports or depends on this module. Provides the
building blocks the SVM check group (SOLANA-PLAN.md) needs — CAIP-2 network refs,
program addresses, ``TransferChecked``/ComputeBudget instruction encoders, and ATA
derivation — mirrored from the x402 Python reference client so our payloads are
byte-faithful to the spec (`specs/schemes/exact/scheme_exact_svm.md`).

Constants and byte encoders are pure/dependency-free. ATA derivation needs the
optional ``[svm]`` extra (``solders``); it imports lazily so importing this module
never requires Solana packages.
"""

from __future__ import annotations

import base64
import binascii
import os
from enum import StrEnum

# --- CAIP-2 network refs (Solana genesis-hash chain ids) ---
SOLANA_MAINNET = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
SOLANA_DEVNET = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
SOLANA_TESTNET = "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z"
SOLANA_NETWORKS = frozenset({SOLANA_MAINNET, SOLANA_DEVNET, SOLANA_TESTNET})

# --- program addresses (base58) ---
TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
ASSOCIATED_TOKEN_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
COMPUTE_BUDGET_PROGRAM = "ComputeBudget111111111111111111111111111111"
MEMO_PROGRAM = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
TOKEN_PROGRAMS = frozenset({TOKEN_PROGRAM, TOKEN_2022_PROGRAM})

# --- instruction discriminators (first data byte) ---
IX_SET_COMPUTE_UNIT_LIMIT = 2
IX_SET_COMPUTE_UNIT_PRICE = 3
IX_TRANSFER_CHECKED = 12

MAX_MEMO_BYTES = 256
DEFAULT_COMPUTE_UNIT_LIMIT = 20000
DEFAULT_COMPUTE_UNIT_PRICE = 1  # microLamports

_U32_MAX = 2**32 - 1
_U64_MAX = 2**64 - 1


class SvmTamper(StrEnum):
    """Structural mutations that a conformant facilitator MUST reject. Each maps to a
    spec error code (SOLANA-PLAN §5) and drives one negative check. Amount/mint/payTo
    mismatches need no tamper — they are just wrong inputs to the normal builder."""

    DROP_COMPUTE_BUDGET = "drop_compute_budget"  # -> ..._instructions_length (Path-1 layout)
    NOT_TRANSFER_CHECKED = "not_transfer_checked"  # -> ..._instruction_not_spl_token_transfer_checked
    DOUBLE_TRANSFER = "double_transfer"  # -> two matching transfers (§1.4 exactly-one)
    FEE_PAYER_IN_ACCOUNTS = "fee_payer_in_accounts"  # -> ..._fee_payer_included_in_instruction_accounts


def is_solana_network(network: str) -> bool:
    """True for a ``solana:*`` CAIP-2 id. Never matches ``eip155:*`` — the switch
    that keeps SVM handling additive and off the EVM path."""
    return network.startswith("solana:")


def is_known_token_program(program: str) -> bool:
    """True iff ``program`` is the SPL Token or Token-2022 program."""
    return program in TOKEN_PROGRAMS


def encode_transfer_checked(amount: int, decimals: int) -> bytes:
    """``TransferChecked`` instruction data: disc(12) + u64 amount (LE) + u8 decimals.
    Same byte layout for SPL Token and Token-2022."""
    if not 0 <= amount <= _U64_MAX:
        raise ValueError("amount out of u64 range")
    if not 0 <= decimals <= 255:
        raise ValueError("decimals out of u8 range")
    return bytes([IX_TRANSFER_CHECKED]) + amount.to_bytes(8, "little") + bytes([decimals])


def encode_set_compute_unit_limit(units: int) -> bytes:
    """ComputeBudget ``SetComputeUnitLimit``: disc(2) + u32 units (LE)."""
    if not 0 <= units <= _U32_MAX:
        raise ValueError("compute unit limit out of u32 range")
    return bytes([IX_SET_COMPUTE_UNIT_LIMIT]) + units.to_bytes(4, "little")


def encode_set_compute_unit_price(micro_lamports: int) -> bytes:
    """ComputeBudget ``SetComputeUnitPrice``: disc(3) + u64 microLamports (LE)."""
    if not 0 <= micro_lamports <= _U64_MAX:
        raise ValueError("compute unit price out of u64 range")
    return bytes([IX_SET_COMPUTE_UNIT_PRICE]) + micro_lamports.to_bytes(8, "little")


def derive_ata(owner: str, mint: str, token_program: str = TOKEN_PROGRAM) -> str:
    """Derive the Associated Token Account for ``owner``+``mint`` under ``token_program``.

    PDA over seeds ``[owner, token_program, mint]`` and the Associated Token Program —
    exactly the derivation the x402 reference and the spec's destination-ATA rule use.
    Requires the ``[svm]`` extra (``solders``).
    """
    try:
        from solders.pubkey import Pubkey
    except ImportError as e:  # pragma: no cover - only hit without the [svm] extra
        raise ImportError(
            "SVM ATA derivation needs the [svm] extra: pip install x402-conformance[svm]"
        ) from e

    ata_program = Pubkey.from_string(ASSOCIATED_TOKEN_PROGRAM)
    seeds = [
        bytes(Pubkey.from_string(owner)),
        bytes(Pubkey.from_string(token_program)),
        bytes(Pubkey.from_string(mint)),
    ]
    ata, _bump = Pubkey.find_program_address(seeds, ata_program)
    return str(ata)


def build_exact_svm_transaction(
    *,
    payer_keypair_bytes: bytes,
    fee_payer: str,
    mint: str,
    decimals: int,
    pay_to: str,
    amount: int,
    recent_blockhash: str,
    memo: str | None = None,
    token_program: str = TOKEN_PROGRAM,
    compute_unit_limit: int = DEFAULT_COMPUTE_UNIT_LIMIT,
    compute_unit_price: int = DEFAULT_COMPUTE_UNIT_PRICE,
    tamper: SvmTamper | None = None,
) -> str:
    """Build a base64, partially-signed ``exact``-SVM transaction (client-signed).

    Mirrors the x402 reference client (``scheme_exact_svm.md``): instructions are
    SetComputeUnitLimit, SetComputeUnitPrice, ``TransferChecked`` (to the ATA derived
    from ``pay_to``+``mint``), then a Memo (``memo`` or a random 16-byte nonce). The
    message ``payer`` is the sponsor's ``feePayer`` — whose signature slot is left as
    a default placeholder for /settle; only the client (payer) signs here. Requires
    the ``[svm]`` extra.

    ``recent_blockhash`` is a base58 blockhash (from RPC live, or a fixed value in
    offline tests). Returns the base64-encoded serialized ``VersionedTransaction``.
    """
    try:
        from solders.hash import Hash
        from solders.instruction import AccountMeta, Instruction
        from solders.keypair import Keypair
        from solders.message import MessageV0
        from solders.pubkey import Pubkey
        from solders.signature import Signature
        from solders.transaction import VersionedTransaction
    except ImportError as e:  # pragma: no cover - only hit without the [svm] extra
        raise ImportError(
            "SVM transaction building needs the [svm] extra: pip install x402-conformance[svm]"
        ) from e

    if memo is not None and len(memo.encode("utf-8")) > MAX_MEMO_BYTES:
        raise ValueError(f"memo exceeds maximum {MAX_MEMO_BYTES} bytes")

    payer = Keypair.from_bytes(payer_keypair_bytes)
    token_prog = Pubkey.from_string(token_program)
    source_ata = Pubkey.from_string(derive_ata(str(payer.pubkey()), mint, token_program))
    dest_ata = Pubkey.from_string(derive_ata(pay_to, mint, token_program))
    compute_budget = Pubkey.from_string(COMPUTE_BUDGET_PROGRAM)

    transfer_ix = Instruction(
        program_id=token_prog,
        accounts=[
            AccountMeta(source_ata, is_signer=False, is_writable=True),
            AccountMeta(Pubkey.from_string(mint), is_signer=False, is_writable=False),
            AccountMeta(dest_ata, is_signer=False, is_writable=True),
            AccountMeta(payer.pubkey(), is_signer=True, is_writable=False),
        ],
        data=encode_transfer_checked(amount, decimals),
    )
    memo_data = memo.encode("utf-8") if memo else binascii.hexlify(os.urandom(16))
    instructions = [
        Instruction(
            program_id=compute_budget,
            accounts=[],
            data=encode_set_compute_unit_limit(compute_unit_limit),
        ),
        Instruction(
            program_id=compute_budget,
            accounts=[],
            data=encode_set_compute_unit_price(compute_unit_price),
        ),
        transfer_ix,
        Instruction(program_id=Pubkey.from_string(MEMO_PROGRAM), accounts=[], data=memo_data),
    ]

    if tamper == SvmTamper.DROP_COMPUTE_BUDGET:
        # Only transfer + memo → 2 instructions, outside the Path-1 3..7 window.
        instructions = [transfer_ix, instructions[3]]
    elif tamper == SvmTamper.DOUBLE_TRANSFER:
        # A second matching TransferChecked — §1.4 requires exactly one.
        instructions = [*instructions, transfer_ix]
    elif tamper == SvmTamper.NOT_TRANSFER_CHECKED:
        # Plain Transfer (discriminator 3) at the transfer position, not TransferChecked (12).
        instructions[2] = Instruction(
            program_id=token_prog,
            accounts=transfer_ix.accounts,
            data=bytes([3]) + amount.to_bytes(8, "little"),
        )
    elif tamper == SvmTamper.FEE_PAYER_IN_ACCOUNTS:
        # Reference the feePayer in the transfer's accounts — breaks §2.1.1 isolation.
        instructions[2] = Instruction(
            program_id=token_prog,
            accounts=[
                *transfer_ix.accounts,
                AccountMeta(Pubkey.from_string(fee_payer), is_signer=False, is_writable=True),
            ],
            data=transfer_ix.data,
        )

    message = MessageV0.try_compile(
        payer=Pubkey.from_string(fee_payer),
        instructions=instructions,
        address_lookup_table_accounts=[],
        recent_blockhash=Hash.from_string(recent_blockhash),
    )
    # VersionedTransaction messages are signed over the 0x80-prefixed message bytes.
    client_signature = payer.sign_message(bytes([0x80]) + bytes(message))
    # Signature order tracks account order: slot 0 = feePayer (unsigned placeholder,
    # filled at /settle), slot 1 = client (payer).
    tx = VersionedTransaction.populate(message, [Signature.default(), client_signature])
    return base64.b64encode(bytes(tx)).decode("utf-8")
