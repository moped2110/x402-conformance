"""Tests for the EIP-3009 payload builder and tamper toolkit.

The keystone test asserts our independent EIP-712 digest is byte-identical to
the x402 reference SDK (used here only as a test-time oracle). If this ever
fails, our signing has drifted from the spec and every active check is suspect.
"""

from __future__ import annotations

import pytest

eth_account = pytest.importorskip("eth_account")

from eth_account import Account
from eth_account.messages import encode_typed_data

from x402_conformance.payload_builder import (
    _TRANSFER_WITH_AUTHORIZATION_TYPES,
    EvmSigner,
    build_exact_eip3009_payload,
    eip712_digest,
    make_expired,
    make_not_yet_valid,
    signature_recovers_to_authorizer,
    tamper_accepted_amount,
    tamper_recipient,
    tamper_signature,
    tamper_value_lower,
)

REQUIREMENTS = {
    "scheme": "exact",
    "network": "eip155:84532",
    "amount": "10000",
    "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
    "maxTimeoutSeconds": 60,
    "extra": {"name": "USDC", "version": "2"},
}

SIGNER = EvmSigner.from_key("0x" + "11" * 32)

_DOMAIN = {
    "name": "USDC",
    "version": "2",
    "chainId": 84532,
    "verifyingContract": REQUIREMENTS["asset"],
}


def _build(**kw):
    return build_exact_eip3009_payload(
        REQUIREMENTS,
        SIGNER,
        valid_after=1740672089,
        valid_before=1740672154,
        nonce="0x" + "ab" * 32,
        **kw,
    )


def _signable_for(auth):
    message = {
        "from": auth["from"],
        "to": auth["to"],
        "value": int(auth["value"]),
        "validAfter": int(auth["validAfter"]),
        "validBefore": int(auth["validBefore"]),
        "nonce": bytes.fromhex(auth["nonce"].removeprefix("0x")),
    }
    return encode_typed_data(_DOMAIN, _TRANSFER_WITH_AUTHORIZATION_TYPES, message)


def test_digest_matches_sdk_oracle() -> None:
    """KEYSTONE: our digest must equal the reference SDK's, byte for byte."""
    sdk_eip712 = pytest.importorskip("x402.mechanisms.evm.eip712")
    sdk_types = pytest.importorskip("x402.mechanisms.evm.types")

    authorization = {
        "from": SIGNER.address,
        "to": REQUIREMENTS["payTo"],
        "value": "10000",
        "validAfter": "1740672089",
        "validBefore": "1740672154",
        "nonce": "0x" + "ab" * 32,
    }
    our_digest = eip712_digest(authorization, 84532, REQUIREMENTS["asset"], "USDC", "2")

    sdk_auth = sdk_types.ExactEIP3009Authorization(
        from_address=authorization["from"],
        to=authorization["to"],
        value=authorization["value"],
        valid_after=authorization["validAfter"],
        valid_before=authorization["validBefore"],
        nonce=authorization["nonce"],
    )
    sdk_digest = sdk_eip712.hash_eip3009_authorization(
        sdk_auth, 84532, REQUIREMENTS["asset"], "USDC", "2"
    )
    assert our_digest == sdk_digest


def test_valid_payload_signature_recovers_to_signer() -> None:
    payload = _build()
    signable = _signable_for(payload["payload"]["authorization"])
    recovered = Account.recover_message(signable, signature=payload["payload"]["signature"])
    assert recovered == SIGNER.address
    assert signature_recovers_to_authorizer(payload, REQUIREMENTS) is True


def test_valid_payload_structure() -> None:
    payload = _build()
    assert payload["x402Version"] == 2
    assert payload["accepted"]["amount"] == "10000"
    assert payload["payload"]["authorization"]["from"] == SIGNER.address
    assert payload["payload"]["authorization"]["to"] == REQUIREMENTS["payTo"]
    assert len(bytes.fromhex(payload["payload"]["signature"].removeprefix("0x"))) == 65
    assert "resource" not in payload


def test_resource_and_extensions_are_emitted_only_when_supplied() -> None:
    payload = _build(
        resource_url="https://api.example.com/premium",
        extensions={"baz": {"info": "echo-me"}},
    )
    assert payload["resource"] == {"url": "https://api.example.com/premium"}
    assert payload["extensions"] == {"baz": {"info": "echo-me"}}


def test_tamper_signature_breaks_recovery() -> None:
    payload = _build()
    tampered = tamper_signature(payload)
    assert tampered["payload"]["signature"] != payload["payload"]["signature"]
    signable = _signable_for(tampered["payload"]["authorization"])
    # A tampered signature must NOT recover to the real signer. Depending on the
    # corruption it either recovers to some other address or is malformed enough
    # that recovery raises — both mean "invalid", which is what the endpoint sees.
    try:
        recovered = Account.recover_message(signable, signature=tampered["payload"]["signature"])
    except Exception:
        return
    assert recovered != SIGNER.address


def test_tamper_value_lower() -> None:
    payload = _build()
    tampered = tamper_value_lower(payload, factor=0.5)
    assert tampered["payload"]["authorization"]["value"] == "5000"
    assert payload["payload"]["authorization"]["value"] == "10000"


def test_tamper_recipient() -> None:
    attacker = "0xdeADBeeF00000000000000000000000000000000"
    tampered = tamper_recipient(_build(), attacker)
    assert tampered["payload"]["authorization"]["to"] == attacker


def test_make_expired() -> None:
    tampered = make_expired(_build(), now=2_000_000_000)
    assert int(tampered["payload"]["authorization"]["validBefore"]) < 2_000_000_000


def test_make_not_yet_valid() -> None:
    tampered = make_not_yet_valid(_build(), now=2_000_000_000)
    assert int(tampered["payload"]["authorization"]["validAfter"]) > 2_000_000_000


def test_tamper_accepted_amount_keeps_signature() -> None:
    payload = _build()
    tampered = tamper_accepted_amount(payload, "1")
    # accepted is lowered, but the signed authorization value is unchanged —
    # exactly the attack RS-NEG-013 probes.
    assert tampered["accepted"]["amount"] == "1"
    assert tampered["payload"]["authorization"]["value"] == "10000"
