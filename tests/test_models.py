"""Internal: wire-schema models parse the spec examples and handle aliases."""

from __future__ import annotations

from conftest import VALID_PAYMENT_REQUIRED

from x402_conformance.models import (
    PaymentRequired,
    PaymentRequirements,
    SettlementResponse,
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
