"""Guard: the eth-account signing surface we depend on stays where we pinned it.

``payload_builder.eip712_digest`` reaches into a *private* eth-account path
(``eth_account.messages._hash_eip191_message``). A minor eth-account bump can
move or rename it, silently breaking every active/on-chain check. pyproject pins
``eth-account>=0.13,<0.14`` for exactly this reason; this test fails loudly if
the pinned surface moves, so the pin can never drift out of sync with reality.
"""

from __future__ import annotations

import pytest

pytest.importorskip("eth_account")


def test_private_hash_path_still_exists() -> None:
    # The exact private import payload_builder.eip712_digest relies on.
    from eth_account.messages import _hash_eip191_message

    assert callable(_hash_eip191_message)


def test_eip712_digest_is_deterministic_and_32_bytes() -> None:
    # Exercise the real code path end-to-end: if the private hash helper moved or
    # changed shape, this raises instead of returning a stable 32-byte digest.
    from x402_conformance.payload_builder import eip712_digest

    authorization = {
        "from": "0x" + "11" * 20,
        "to": "0x" + "22" * 20,
        "value": "1000000",
        "validAfter": "0",
        "validBefore": "9999999999",
        "nonce": "0x" + "ab" * 32,
    }
    digest = eip712_digest(
        authorization,
        chain_id=84532,
        verifying_contract="0x" + "33" * 20,
        token_name="USD Coin",
        token_version="2",
    )
    assert isinstance(digest, bytes) and len(digest) == 32
    # Deterministic: same inputs → same digest.
    again = eip712_digest(
        authorization,
        chain_id=84532,
        verifying_contract="0x" + "33" * 20,
        token_name="USD Coin",
        token_version="2",
    )
    assert digest == again
