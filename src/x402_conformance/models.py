"""Pydantic models for x402 V2 wire schemas.

Models mirror the spec (CORE = specs/x402-specification-v2.md). Unknown fields
remain allowed for forward compatibility, but wire values are strict: JSON
strings are never coerced to numbers or booleans and finite/positive constraints
are enforced where the protocol requires them.
"""

from __future__ import annotations

import re
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, FiniteFloat, model_validator

_EVM_TX_HASH = re.compile(r"^0x[0-9a-fA-F]{64}$")


class WireModel(BaseModel):
    """Forward-compatible, type-strict base for untrusted wire documents."""

    model_config = ConfigDict(populate_by_name=True, extra="allow", strict=True)


class ResourceInfo(WireModel):
    """CORE §5.1.2 ResourceInfo."""

    url: Annotated[str, Field(min_length=1)]
    description: str | None = None
    mime_type: str | None = Field(default=None, alias="mimeType")
    service_name: str | None = Field(default=None, alias="serviceName")
    tags: list[str] | None = None
    icon_url: str | None = Field(default=None, alias="iconUrl")


class PaymentRequirements(WireModel):
    """CORE §5.1.2 PaymentRequirements (one entry of ``accepts``)."""

    scheme: Annotated[str, Field(min_length=1)]
    network: Annotated[str, Field(min_length=1)]
    amount: Annotated[str, Field(min_length=1)]
    asset: Annotated[str, Field(min_length=1)]
    pay_to: Annotated[str, Field(min_length=1, alias="payTo")]
    max_timeout_seconds: Annotated[FiniteFloat, Field(gt=0, alias="maxTimeoutSeconds")]
    extra: dict[str, object] | None = None


class PaymentRequired(WireModel):
    """CORE §5.1 PaymentRequired (decoded PAYMENT-REQUIRED header)."""

    x402_version: int = Field(alias="x402Version")
    error: str | None = None
    resource: ResourceInfo
    accepts: list[PaymentRequirements]
    extensions: dict[str, object] | None = None


class SettlementResponse(WireModel):
    """CORE §5.3 SettlementResponse (decoded PAYMENT-RESPONSE header)."""

    success: bool
    transaction: str
    network: Annotated[str, Field(min_length=1)]
    error_reason: str | None = Field(default=None, alias="errorReason")
    payer: str | None = None
    amount: str | None = None
    extensions: dict[str, object] | None = None

    @model_validator(mode="after")
    def validate_transaction(self) -> SettlementResponse:
        """A successful settlement must carry a chain-valid transaction id."""

        if self.success:
            if not self.transaction:
                raise ValueError("successful settlement requires a transaction")
            if self.network.startswith("eip155:") and not _EVM_TX_HASH.fullmatch(self.transaction):
                raise ValueError("EVM settlement transaction must be a 32-byte 0x hash")
        elif self.transaction:
            raise ValueError("failed settlement must not carry a transaction")
        return self


class VerifyResponse(WireModel):
    """CORE §7.1 facilitator ``/verify`` response."""

    is_valid: bool = Field(alias="isValid")
    invalid_reason: str | None = Field(default=None, alias="invalidReason")
    payer: str | None = None

    @model_validator(mode="after")
    def validate_reason(self) -> VerifyResponse:
        """Enforce consistency between facilitator validity and invalidReason."""
        if self.is_valid and self.invalid_reason is not None:
            raise ValueError("valid verification must not carry invalidReason")
        if not self.is_valid and not self.invalid_reason:
            raise ValueError("invalid verification requires invalidReason")
        return self


class SupportedKind(WireModel):
    """One entry in a facilitator ``/supported.kinds`` array."""

    x402_version: int = Field(alias="x402Version")
    scheme: Annotated[str, Field(min_length=1)]
    network: Annotated[str, Field(min_length=1)]


class SupportedResponse(WireModel):
    """CORE §7.3 facilitator ``/supported`` response."""

    kinds: list[SupportedKind]
    extensions: list[str]
    signers: dict[str, list[str]]


class DiscoveryItem(WireModel):
    """One resource returned by the v2 discovery API."""

    resource: Annotated[str, Field(min_length=1)]
    type: Annotated[str, Field(min_length=1)]
    x402_version: int = Field(alias="x402Version")
    accepts: list[PaymentRequirements]
    last_updated: int = Field(alias="lastUpdated", ge=0)
    metadata: dict[str, Any] | None = None


class DiscoveryPagination(WireModel):
    limit: int = Field(ge=0)
    offset: int = Field(ge=0)
    total: int = Field(ge=0)


class DiscoveryResponse(WireModel):
    """CORE §8.1 discovery response envelope."""

    x402_version: int = Field(alias="x402Version")
    items: list[DiscoveryItem]
    pagination: DiscoveryPagination
