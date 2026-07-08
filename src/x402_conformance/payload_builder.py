"""Build and deliberately tamper x402 `exact`/eip3009 payment payloads.

This is the foundation for the active negative-test group (RS-NEG): we sign a
valid EIP-3009 ``TransferWithAuthorization`` and then mutate exactly one aspect
per test case so the endpoint is forced to reject for one specific reason.

**Independence:** signing is implemented directly on top of ``eth-account`` —
the tester does NOT depend on the x402 SDK at runtime, so it cannot inherit the
SDK's bugs. The SDK is used only as a *test-time oracle* (see tests): we assert
our EIP-712 digest is byte-identical to the reference implementation's.

``eth-account`` is an optional dependency. Install with::

    pip install x402-conformance[evm]

No mainnet keys, ever. Signers are testnet-only throwaway keys (see CLAUDE.md).
"""

from __future__ import annotations

import copy
import secrets
import time
from dataclasses import dataclass
from typing import Any

try:
    from eth_account import Account
    from eth_account.messages import encode_typed_data
    from eth_account.signers.local import LocalAccount

    _EVM_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without the [evm] extra
    _EVM_AVAILABLE = False


_TRANSFER_WITH_AUTHORIZATION_TYPES: dict[str, list[dict[str, str]]] = {
    "TransferWithAuthorization": [
        {"name": "from", "type": "address"},
        {"name": "to", "type": "address"},
        {"name": "value", "type": "uint256"},
        {"name": "validAfter", "type": "uint256"},
        {"name": "validBefore", "type": "uint256"},
        {"name": "nonce", "type": "bytes32"},
    ]
}


def _require_evm() -> None:
    if not _EVM_AVAILABLE:
        raise RuntimeError(
            "EVM payload signing requires eth-account. Install with: "
            "pip install x402-conformance[evm]"
        )


def _chain_id_from_caip2(network: str) -> int:
    """Extract the integer chain id from an ``eip155:<id>`` CAIP-2 string."""
    if not network.startswith("eip155:"):
        raise ValueError(f"not an EVM (eip155) network: {network!r}")
    return int(network.split(":", 1)[1])


@dataclass
class EvmSigner:
    """A testnet EVM signer. Wraps an eth-account LocalAccount."""

    account: LocalAccount

    @classmethod
    def from_key(cls, private_key: str) -> EvmSigner:
        _require_evm()
        return cls(Account.from_key(private_key))

    @classmethod
    def random(cls) -> EvmSigner:
        """A fresh random throwaway signer (tests, never funded)."""
        _require_evm()
        return cls(Account.from_key("0x" + secrets.token_hex(32)))

    @property
    def address(self) -> str:
        return self.account.address


def eip712_digest(
    authorization: dict[str, Any],
    chain_id: int,
    verifying_contract: str,
    token_name: str,
    token_version: str,
) -> bytes:
    """Compute the EIP-712 digest for an EIP-3009 authorization.

    Independent of the x402 SDK — proven byte-identical to it in the tests.
    """
    _require_evm()
    domain = {
        "name": token_name,
        "version": token_version,
        "chainId": chain_id,
        "verifyingContract": verifying_contract,
    }
    message = {
        "from": authorization["from"],
        "to": authorization["to"],
        "value": int(authorization["value"]),
        "validAfter": int(authorization["validAfter"]),
        "validBefore": int(authorization["validBefore"]),
        "nonce": bytes.fromhex(str(authorization["nonce"]).removeprefix("0x")),
    }
    signable = encode_typed_data(domain, _TRANSFER_WITH_AUTHORIZATION_TYPES, message)
    from eth_account.messages import _hash_eip191_message

    return _hash_eip191_message(signable)


def build_exact_eip3009_payload(
    requirements: dict[str, Any],
    signer: EvmSigner,
    *,
    valid_after: int | None = None,
    valid_before: int | None = None,
    nonce: str | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    """Build a fully valid, signed `exact`/eip3009 PaymentPayload.

    ``requirements`` is one entry from a PaymentRequired ``accepts`` array.
    Time window and nonce can be pinned for deterministic tests; otherwise a
    sensible window around ``now`` and a random nonce are used.
    """
    _require_evm()
    extra = requirements.get("extra") or {}
    token_name = extra.get("name")
    token_version = extra.get("version")
    if not token_name or not token_version:
        raise ValueError("requirements.extra must contain 'name' and 'version' for eip3009")

    chain_id = _chain_id_from_caip2(requirements["network"])
    now = now if now is not None else int(time.time())
    # Canonical client defaults since x402#2601 ("validAfter patch"): validAfter = 0
    # and maxTimeoutSeconds = 300. validAfter = 0 means "valid from genesis", which
    # every facilitator accepts (rule is validAfter <= now); we mirror the reference
    # client so generated payloads match real-world client behaviour.
    valid_after = valid_after if valid_after is not None else 0
    valid_before = (
        valid_before
        if valid_before is not None
        else now + int(requirements.get("maxTimeoutSeconds", 300))
    )
    nonce = nonce if nonce is not None else "0x" + secrets.token_hex(32)

    authorization = {
        "from": signer.address,
        "to": requirements["payTo"],
        "value": str(requirements["amount"]),
        "validAfter": str(valid_after),
        "validBefore": str(valid_before),
        "nonce": nonce,
    }
    signature = _sign_authorization(
        authorization, signer, chain_id, requirements["asset"], token_name, token_version
    )

    return {
        "x402Version": 2,
        "resource": {"url": ""},  # filled by caller if needed
        "accepted": copy.deepcopy(requirements),
        "payload": {"signature": signature, "authorization": authorization},
        "extensions": {},
    }


def _sign_authorization(
    authorization: dict[str, Any],
    signer: EvmSigner,
    chain_id: int,
    verifying_contract: str,
    token_name: str,
    token_version: str,
) -> str:
    domain = {
        "name": token_name,
        "version": token_version,
        "chainId": chain_id,
        "verifyingContract": verifying_contract,
    }
    message = {
        "from": authorization["from"],
        "to": authorization["to"],
        "value": int(authorization["value"]),
        "validAfter": int(authorization["validAfter"]),
        "validBefore": int(authorization["validBefore"]),
        "nonce": bytes.fromhex(str(authorization["nonce"]).removeprefix("0x")),
    }
    signable = encode_typed_data(domain, _TRANSFER_WITH_AUTHORIZATION_TYPES, message)
    signed = signer.account.sign_message(signable)
    return signed.signature.to_0x_hex()


# --------------------------------------------------------------------------
# Tamper toolkit — each function returns a NEW payload with exactly one defect.
# Maps to the RS-NEG catalog cases. The endpoint must reject each for the
# stated reason; accepting any of them is a critical conformance failure.
# --------------------------------------------------------------------------


def tamper_signature(payload: dict[str, Any]) -> dict[str, Any]:
    """RS-NEG-003: flip the signature so it no longer recovers to `from`."""
    out = copy.deepcopy(payload)
    sig = out["payload"]["signature"]
    # flip one byte in the r-component (keep length/format valid)
    body = bytearray(bytes.fromhex(sig.removeprefix("0x")))
    body[0] ^= 0xFF
    out["payload"]["signature"] = "0x" + body.hex()
    return out


def tamper_value_lower(payload: dict[str, Any], factor: float = 0.5) -> dict[str, Any]:
    """RS-NEG-005: authorize less than required (underpayment)."""
    out = copy.deepcopy(payload)
    new_value = str(max(1, int(int(out["payload"]["authorization"]["value"]) * factor)))
    out["payload"]["authorization"]["value"] = new_value
    return out


def tamper_recipient(payload: dict[str, Any], attacker: str) -> dict[str, Any]:
    """RS-NEG-007: redirect funds to a different address."""
    out = copy.deepcopy(payload)
    out["payload"]["authorization"]["to"] = attacker
    return out


def tamper_from(payload: dict[str, Any], claimed_from: str) -> dict[str, Any]:
    """RS-NEG-004: keep the (valid) signature but claim a DIFFERENT `from`. The
    signature still recovers to the real signer, so recovered != authorization.from
    — a foreign/stolen signature reused under someone else's identity."""
    out = copy.deepcopy(payload)
    out["payload"]["authorization"]["from"] = claimed_from
    return out


def make_expired(payload: dict[str, Any], now: int | None = None) -> dict[str, Any]:
    """RS-NEG-008: validBefore in the past."""
    out = copy.deepcopy(payload)
    now = now if now is not None else int(time.time())
    out["payload"]["authorization"]["validBefore"] = str(now - 1)
    return out


def make_not_yet_valid(payload: dict[str, Any], now: int | None = None) -> dict[str, Any]:
    """RS-NEG-009: validAfter in the future."""
    out = copy.deepcopy(payload)
    now = now if now is not None else int(time.time())
    out["payload"]["authorization"]["validAfter"] = str(now + 3600)
    return out


def tamper_accepted_amount(payload: dict[str, Any], new_amount: str) -> dict[str, Any]:
    """RS-NEG-013: lower the advertised amount in `accepted` (client-supplied).

    The server must validate against ITS OWN requirements, not the value the
    client echoes back.
    """
    out = copy.deepcopy(payload)
    out["accepted"]["amount"] = new_amount
    return out
