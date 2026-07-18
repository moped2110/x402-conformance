"""Fail-closed safety boundaries for payment-bearing conformance probes.

The suite is a test tool, not a wallet.  It may sign/send payments only for a
small, reviewed set of local/test networks.  There is deliberately no runtime
override for mainnet or unknown networks.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx


class SafetyViolation(ValueError):
    """A requested operation could sign or send value outside the safe boundary."""


# Keep this list intentionally short.  Adding a network is a security decision:
# document it, add a regression test, and review its canonical CAIP-2 identifier.
_ALLOWED_EVM_NETWORKS: dict[str, str] = {
    "eip155:1337": "local development chain",
    "eip155:31337": "Anvil/Hardhat local chain",
    "eip155:84532": "Base Sepolia",
    "eip155:11155111": "Ethereum Sepolia",
}

_ALLOWED_SVM_NETWORKS: dict[str, str] = {
    "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1": "Solana devnet",
    "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z": "Solana testnet",
}

_REDIRECT_STATUS = frozenset({301, 302, 303, 307, 308})


def _network_chain_id(network: str) -> int:
    namespace, separator, reference = network.partition(":")
    if namespace != "eip155" or not separator or not reference.isdecimal():
        raise SafetyViolation(f"payment network {network!r} is not a valid EVM CAIP-2 id")
    return int(reference)


def read_rpc_chain_id(rpc_url: str, *, timeout: float = 10.0) -> int:
    """Read ``eth_chainId`` without following redirects.

    Redirected RPC requests are rejected: an RPC URL can contain credentials and
    its chain identity is part of the payment safety decision.
    """

    try:
        response = httpx.post(
            rpc_url,
            json={"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []},
            timeout=timeout,
            follow_redirects=False,
        )
    except httpx.HTTPError as exc:
        raise SafetyViolation(f"cannot verify RPC chain id: {type(exc).__name__}") from exc
    if response.status_code in _REDIRECT_STATUS:
        raise SafetyViolation(f"RPC redirect blocked (HTTP {response.status_code})")
    if response.status_code != 200:
        raise SafetyViolation(f"cannot verify RPC chain id: HTTP {response.status_code}")
    try:
        body: Any = response.json()
        raw = body["result"] if isinstance(body, dict) else None
        if not isinstance(raw, str) or not raw.startswith("0x"):
            raise ValueError("result is not a hex string")
        chain_id = int(raw, 16)
    except (KeyError, TypeError, ValueError) as exc:
        raise SafetyViolation("cannot verify RPC chain id: malformed eth_chainId response") from exc
    if chain_id <= 0:
        raise SafetyViolation("cannot verify RPC chain id: invalid chain id")
    return chain_id


@dataclass(frozen=True)
class SafetyPolicy:
    """Central allowlist policy used before any payment payload is built."""

    allowed_evm_networks: frozenset[str] = frozenset(_ALLOWED_EVM_NETWORKS)
    allowed_svm_networks: frozenset[str] = frozenset(_ALLOWED_SVM_NETWORKS)

    def require_safe_network(self, network: object) -> str:
        if not isinstance(network, str) or not network:
            raise SafetyViolation("payment requirement has no valid CAIP-2 network")
        if network.startswith("eip155:"):
            _network_chain_id(network)
            if network not in self.allowed_evm_networks:
                raise SafetyViolation(
                    f"payment network {network!r} is not in the testnet/local allowlist"
                )
            return network
        if network.startswith("solana:"):
            if network not in self.allowed_svm_networks:
                raise SafetyViolation(
                    f"payment network {network!r} is not in the testnet/local allowlist"
                )
            return network
        raise SafetyViolation(f"payment network {network!r} is unsupported and denied")

    def require_matching_rpc(self, network: object, rpc_url: str | None) -> int:
        safe_network = self.require_safe_network(network)
        if not safe_network.startswith("eip155:"):
            raise SafetyViolation("eth_chainId validation is only available for EVM payments")
        if not rpc_url:
            raise SafetyViolation("a matching --rpc-url is required for settlement tests")
        expected = _network_chain_id(safe_network)
        actual = read_rpc_chain_id(rpc_url)
        if actual != expected:
            raise SafetyViolation(
                f"RPC chain mismatch: requirement is {safe_network}, RPC returned eip155:{actual}"
            )
        return actual


DEFAULT_SAFETY_POLICY = SafetyPolicy()
