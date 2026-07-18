"""Internal: wire-schema models parse the spec examples and handle aliases."""

from __future__ import annotations

import math

import pytest
from conftest import VALID_PAYMENT_REQUIRED
from pydantic import ValidationError

from x402_conformance.models import (
    DiscoveryResponse,
    PaymentRequired,
    PaymentRequirements,
    SettlementResponse,
    SupportedResponse,
    VerifyResponse,
)


def test_payment_required_parses_spec_example() -> None:
    pr = PaymentRequired.model_validate(VALID_PAYMENT_REQUIRED)
    assert pr.x402_version == 2
    assert pr.resource.url == "https://api.example.com/premium-data"
    assert len(pr.accepts) == 1


def test_payment_requirements_aliases() -> None:
    req = PaymentRequirements.model_validate(VALID_PAYMENT_REQUIRED["accepts"][0])
    # camelCase wire names map to snake_case attributes
    assert req.pay_to == "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"
    assert req.max_timeout_seconds == 60
    assert req.network == "eip155:84532"


def test_extra_fields_are_allowed_not_rejected() -> None:
    data = dict(VALID_PAYMENT_REQUIRED)
    data["someFutureField"] = {"a": 1}
    # unknown fields must not break parsing (forward-compat)
    pr = PaymentRequired.model_validate(data)
    assert pr.x402_version == 2


def test_settlement_response_aliases() -> None:
    sr = SettlementResponse.model_validate(
        {
            "success": False,
            "errorReason": "insufficient_funds",
            "transaction": "",
            "network": "eip155:84532",
        }
    )
    assert sr.success is False
    assert sr.error_reason == "insufficient_funds"


def test_resourceinfo_optional_fields() -> None:
    pr = PaymentRequired.model_validate(
        {
            "x402Version": 2,
            "resource": {"url": "https://x.example/y"},  # only required field
            "accepts": [VALID_PAYMENT_REQUIRED["accepts"][0]],
        }
    )
    assert pr.resource.description is None
    assert pr.resource.icon_url is None


@pytest.mark.parametrize("timeout", ["60", True, 0, -1, math.nan, math.inf])
def test_payment_requirements_reject_schema_invalid_timeout(timeout: object) -> None:
    req = dict(VALID_PAYMENT_REQUIRED["accepts"][0])
    req["maxTimeoutSeconds"] = timeout
    with pytest.raises(ValidationError):
        PaymentRequirements.model_validate(req)


def test_wire_integer_and_boolean_types_are_not_coerced() -> None:
    data = dict(VALID_PAYMENT_REQUIRED)
    data["x402Version"] = True
    with pytest.raises(ValidationError):
        PaymentRequired.model_validate(data)

    with pytest.raises(ValidationError):
        SettlementResponse.model_validate(
            {
                "success": "true",
                "transaction": "0x" + "ab" * 32,
                "network": "eip155:84532",
            }
        )


def test_successful_evm_settlement_requires_canonical_tx_hash() -> None:
    with pytest.raises(ValidationError):
        SettlementResponse.model_validate(
            {"success": True, "transaction": "0x1234", "network": "eip155:84532"}
        )


def test_failed_settlement_must_not_claim_a_transaction() -> None:
    with pytest.raises(ValidationError):
        SettlementResponse.model_validate(
            {
                "success": False,
                "transaction": "0x" + "ab" * 32,
                "network": "eip155:84532",
            }
        )


def test_strict_facilitator_models_allow_future_fields() -> None:
    verified = VerifyResponse.model_validate(
        {"isValid": True, "payer": "0xabc", "futureProof": {"version": 3}}
    )
    assert verified.is_valid is True
    supported = SupportedResponse.model_validate(
        {
            "kinds": [{"x402Version": 2, "scheme": "exact", "network": "eip155:84532"}],
            "extensions": [],
            "signers": {"eip155:*": ["0xabc"]},
            "futureProof": True,
        }
    )
    assert supported.kinds[0].x402_version == 2


def test_discovery_model_is_strict_and_complete() -> None:
    doc = {
        "x402Version": 2,
        "items": [
            {
                "resource": "https://api.example/data",
                "type": "http",
                "x402Version": 2,
                "accepts": [VALID_PAYMENT_REQUIRED["accepts"][0]],
                "lastUpdated": 1703123456,
            }
        ],
        "pagination": {"limit": 20, "offset": 0, "total": 1},
    }
    assert DiscoveryResponse.model_validate(doc).pagination.total == 1
    doc["pagination"]["total"] = "1"
    with pytest.raises(ValidationError):
        DiscoveryResponse.model_validate(doc)
