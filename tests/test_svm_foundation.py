"""SVM (Solana) foundation: CAIP-2, instruction encoders, ATA derivation.

Additive — these exercise the new svm module only; no EVM path is touched. The
whole file skips when the [svm] extra (solders) isn't installed, so the core CI
stays green without Solana packages.
"""

from __future__ import annotations

import pytest

pytest.importorskip("solders")  # ATA derivation needs the [svm] extra

from x402_conformance.svm import (  # noqa: E402
    IX_TRANSFER_CHECKED,
    SOLANA_DEVNET,
    SOLANA_MAINNET,
    TOKEN_2022_PROGRAM,
    TOKEN_PROGRAM,
    derive_ata,
    encode_set_compute_unit_limit,
    encode_set_compute_unit_price,
    encode_transfer_checked,
    is_known_token_program,
    is_solana_network,
)

USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
OWNER = "CfxHiXqdZq3gYgzadgdtd84tYr7CHNEgjRiii3WeJKz4"


def test_is_solana_network_never_matches_evm() -> None:
    assert is_solana_network(SOLANA_MAINNET)
    assert is_solana_network(SOLANA_DEVNET)
    assert not is_solana_network("eip155:84532")
    assert not is_solana_network("eip155:1")


def test_known_token_programs() -> None:
    assert is_known_token_program(TOKEN_PROGRAM)
    assert is_known_token_program(TOKEN_2022_PROGRAM)
    assert not is_known_token_program(USDC_MINT)


def test_transfer_checked_encoding() -> None:
    # disc 12 + amount 1000 (u64 LE) + decimals 6
    data = encode_transfer_checked(1000, 6)
    assert data == bytes([IX_TRANSFER_CHECKED]) + (1000).to_bytes(8, "little") + bytes([6])
    assert data.hex() == "0ce803000000000000" + "06"


def test_compute_budget_encoding() -> None:
    assert encode_set_compute_unit_limit(20000) == bytes([2]) + (20000).to_bytes(4, "little")
    assert encode_set_compute_unit_price(1) == bytes([3]) + (1).to_bytes(8, "little")


def test_encoders_reject_out_of_range() -> None:
    with pytest.raises(ValueError):
        encode_transfer_checked(-1, 6)
    with pytest.raises(ValueError):
        encode_transfer_checked(1, 256)  # decimals > u8
    with pytest.raises(ValueError):
        encode_set_compute_unit_limit(2**32)  # > u32


def test_derive_ata_pinned_and_deterministic() -> None:
    ata = derive_ata(OWNER, USDC_MINT, TOKEN_PROGRAM)
    # Pinned vector (owner + USDC mint under SPL Token program). Guards against a
    # silent change in the derivation (seed order / program id).
    assert ata == "3hhWRPGpaMtZFL6cDHcC4deUNLh7S36VN66zKddCTwUL"
    assert derive_ata(OWNER, USDC_MINT, TOKEN_PROGRAM) == ata


def test_spl_and_token2022_atas_differ() -> None:
    # Same owner+mint under a different token program derives a different ATA —
    # exactly why the destination-ATA check must be program-aware.
    assert derive_ata(OWNER, USDC_MINT, TOKEN_PROGRAM) != derive_ata(
        OWNER, USDC_MINT, TOKEN_2022_PROGRAM
    )
