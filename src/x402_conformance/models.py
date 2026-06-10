"""Pydantic models for x402 V2 wire schemas.

Models mirror the spec (CORE = specs/x402-specification-v2.md). They are
deliberately permissive (``extra="allow"``) so that a single unknown field does
not abort parsing: fine-grained constraint violations are reported by
individual checks, not by the parser.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ResourceInfo(BaseModel):
    """CORE §5.1.2 ResourceInfo."""

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    url: str
    description: str | None = None
    mime_type: str | None = Field(default=None, alias="mimeType")
    service_name: str | None = Field(default=None, alias="serviceName")
    tags: list[str] | None = None
    icon_url: str | None = Field(default=None, alias="iconUrl")


class PaymentRequirements(BaseModel):
    """CORE §5.1.2 PaymentRequirements (one entry of ``accepts``)."""

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    scheme: str
    network: str
    amount: str
    asset: str
    pay_to: str = Field(alias="payTo")
    max_timeout_seconds: float = Field(alias="maxTimeoutSeconds")
    extra: dict[str, object] | None = None


class PaymentRequired(BaseModel):
    """CORE §5.1 PaymentRequired (decoded PAYMENT-REQUIRED header)."""

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    x402_version: int = Field(alias="x402Version")
    error: str | None = None
    resource: ResourceInfo
    accepts: list[PaymentRequirements]
    extensions: dict[str, object] | None = None


class SettlementResponse(BaseModel):
    """CORE §5.3 SettlementResponse (decoded PAYMENT-RESPONSE header)."""

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    success: bool
    transaction: str
    network: str
    error_reason: str | None = Field(default=None, alias="errorReason")
    payer: str | None = None
    amount: str | None = None
    extensions: dict[str, object] | None = None
