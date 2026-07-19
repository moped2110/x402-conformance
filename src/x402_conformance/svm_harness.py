"""In-process SVM settlement harness for the ``exact`` scheme (SOLANA-PLAN §2).

LiteSVM is Solana's in-process runtime — the SVM answer to Anvil. It bundles the SPL
Token, Token-2022 and Associated-Token programs, so a ``TransferChecked`` executes for
real without an external ``solana-test-validator`` (the plan's original harness), which
keeps the SVM check group runnable in ordinary CI.

The harness writes a mint and the payer/merchant token accounts directly with
``set_account`` (deterministic, no setup transactions), funds the sponsor with SOL for
fees, then settles a client-signed ``exact`` transaction by filling the ``feePayer``
signature slot — mirroring what a real facilitator does at ``/settle``. Only the
``exact`` transfer itself executes on the runtime.

Purely additive and behind the ``[svm]`` extra: importing needs ``solders``/``solana``.
Money invariant untouched — LiteSVM is a local test VM, never a real chain.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any

from .svm import TOKEN_PROGRAM, derive_ata


@dataclass(frozen=True)
class SettlementOutcome:
    """The result of submitting one exact-SVM transaction to the local runtime."""

    settled: bool
    #: Runtime error string when it failed on-chain, else None.
    error: str | None


class SvmHarness:
    """A LiteSVM environment with one mint and funded payer/merchant token accounts."""

    def __init__(self, *, decimals: int = 6, token_program: str = TOKEN_PROGRAM) -> None:
        """Stand up the runtime, mint, and both token accounts (payer funded)."""
        from solders.keypair import Keypair
        from solders.litesvm import LiteSVM
        from solders.pubkey import Pubkey

        # Blockhash checking off so a test can build with any recent blockhash; signature
        # verification stays ON so a bad client/feePayer signature is still rejected.
        self._svm = LiteSVM().with_blockhash_check(False)
        self.decimals = decimals
        self._token_program = Pubkey.from_string(token_program)
        self.token_program = token_program

        self.payer = Keypair()  # the client
        self.fee_payer = Keypair()  # the sponsor / feePayer
        self.merchant = Keypair()
        self.mint = Keypair().pubkey()

        self._svm.airdrop(self.fee_payer.pubkey(), 1_000_000_000)  # SOL for fees

        self._write_mint()
        self.payer_ata = Pubkey.from_string(
            derive_ata(str(self.payer.pubkey()), str(self.mint), token_program)
        )
        self.merchant_ata = Pubkey.from_string(
            derive_ata(str(self.merchant.pubkey()), str(self.mint), token_program)
        )
        self._write_token_account(self.payer_ata, self.payer.pubkey(), 1_000_000_000_000)
        self._write_token_account(self.merchant_ata, self.merchant.pubkey(), 0)

    def _account(self, data: bytes) -> Any:
        """Build a rent-exempt owned account holding ``data`` under the token program."""
        from solders.account import Account

        lamports = self._svm.minimum_balance_for_rent_exemption(len(data))
        return Account(
            lamports=lamports,
            data=data,
            owner=self._token_program,
            executable=False,
            rent_epoch=0,
        )

    def _write_mint(self) -> None:
        """Write an initialised SPL mint account directly into the runtime."""
        from spl.token._layouts import MINT_LAYOUT

        data = MINT_LAYOUT.build(
            {
                "mint_authority_option": 1,
                "mint_authority": bytes(self.payer.pubkey()),
                "supply": 1_000_000_000_000,
                "decimals": self.decimals,
                "is_initialized": 1,
                "freeze_authority_option": 0,
                "freeze_authority": bytes(32),
            }
        )
        self._svm.set_account(self.mint, self._account(bytes(data)))

    def _write_token_account(self, ata: Any, owner: Any, amount: int) -> None:
        """Write an initialised token account (balance ``amount``) into the runtime."""
        from spl.token._layouts import ACCOUNT_LAYOUT

        data = ACCOUNT_LAYOUT.build(
            {
                "mint": bytes(self.mint),
                "owner": bytes(owner),
                "amount": amount,
                "delegate_option": 0,
                "delegate": bytes(32),
                "state": 1,  # initialised
                "is_native_option": 0,
                "is_native": 0,
                "delegated_amount": 0,
                "close_authority_option": 0,
                "close_authority": bytes(32),
            }
        )
        self._svm.set_account(ata, self._account(bytes(data)))

    def latest_blockhash(self) -> str:
        """The runtime's current blockhash, for building a transaction against it."""
        return str(self._svm.latest_blockhash())

    def settle(self, b64_transaction: str) -> SettlementOutcome:
        """Fill the feePayer signature slot and submit; report on-chain success.

        The client already signed the message; the sponsor (feePayer) signs the same
        ``0x80``-prefixed message bytes and takes signature slot 0, exactly as a
        facilitator would at ``/settle``.
        """
        from solders.transaction import VersionedTransaction

        tx = VersionedTransaction.from_bytes(base64.b64decode(b64_transaction))
        message = tx.message
        fee_signature = self.fee_payer.sign_message(bytes([0x80]) + bytes(message))
        signed = VersionedTransaction.populate(message, [fee_signature, tx.signatures[1]])
        result = self._svm.send_transaction(signed)
        ok = _succeeded(result)
        return SettlementOutcome(settled=ok, error=None if ok else str(result))

    def token_balance(self, ata: Any) -> int:
        """Read the SPL token balance of one account address from the runtime."""
        from spl.token._layouts import ACCOUNT_LAYOUT

        account = self._svm.get_account(ata)
        if account is None:
            return 0
        return int(ACCOUNT_LAYOUT.parse(bytes(account.data)).amount)


def _succeeded(result: object) -> bool:
    """True if a LiteSVM transaction result is a success, not a failure metadata."""
    from solders.transaction_metadata import FailedTransactionMetadata

    return not isinstance(result, FailedTransactionMetadata)
