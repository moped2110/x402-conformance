"""PQC test-key safety boundary tests."""

import pytest

from x402_conformance.safety import SafetyViolation, require_pqc_test_key_network


def test_pqc_fixture_key_allowed_on_testnet() -> None:
    require_pqc_test_key_network("TEST-ONLY-pqc", "eip155:31337")


@pytest.mark.parametrize("network", ["eip155:1", "eip155:8453", "solana:mainnet"])
def test_pqc_fixture_key_denied_on_mainnet(network: str) -> None:
    with pytest.raises(SafetyViolation, match="PQC test key"):
        require_pqc_test_key_network("TEST-ONLY-pqc", network)
