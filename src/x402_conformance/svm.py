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

_U32_MAX = 2**32 - 1
_U64_MAX = 2**64 - 1


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
