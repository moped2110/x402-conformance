"""Pydantic models for x402 V2 wire schemas.

Models mirror the spec (CORE = specs/x402-specification-v2.md). Unknown fields
remain allowed for forward compatibility, but wire values are strict: JSON
strings are never coerced to numbers or booleans and finite/positive constraints
are enforced where the protocol requires them.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, FiniteFloat, field_validator, model_validator

_EVM_TX_HASH = re.compile(r"^0x[0-9a-fA-F]{64}$")
#: An ISO 8601 calendar date-time, as CORE §8.3 types `lastUpdated` since x402#3067
#: (`"2025-08-09T01:07:04.005Z"`). The time part is required — the field is a
#: timestamp — and the offset is optional, because ISO 8601 permits local time and
#: failing a Bazaar for the omission would be stricter than the specification.
_ISO8601_DATETIME = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}(:\d{2}(\.\d{1,9})?)?([Zz]|[+-]\d{2}(:?\d{2})?)?$"
)


def is_iso8601_timestamp(value: object) -> bool:
    """Recognize an ISO 8601 date-time string that names a real instant."""
    if not isinstance(value, str) or _ISO8601_DATETIME.fullmatch(value) is None:
        return False
    normalized = value.upper()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    # The regex fixes the shape; fromisoformat rejects impossible values such as
    # month 13 or 25:00. Nanosecond precision is legal ISO 8601 but beyond what
    # datetime parses, so the fraction is cut to microseconds first.
    normalized = re.sub(r"(\.\d{6})\d+", r"\1", normalized)
    try:
        datetime.fromisoformat(normalized)
    except ValueError:
        return False
    return True


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
        """A successful settlement must carry a chain-valid transaction id.

        A failed one may carry one too. CORE §5.3.2 says ``transaction`` is empty
        "if no transaction was broadcast", and a broadcast can fail: either it was
        never confirmed (``settlement_pending``, which MUST carry the hash,
        x402#3083) or it reverted. This model used to reject every failed response
        with a hash, so a spec-conformant pending answer read as malformed.

        Whether a particular failure may carry a hash is a *semantic* rule and lives
        in the checks that mean it: a rejected invalid payment must not have been
        broadcast (RS-NEG, FA-SET-002), and a pending one must name its broadcast
        (FA-SET-004, RS-PAY-002).
        """

        if self.success:
            if not self.transaction:
                raise ValueError("successful settlement requires a transaction")
            if self.network.startswith("eip155:") and not _EVM_TX_HASH.fullmatch(self.transaction):
                raise ValueError("EVM settlement transaction must be a 32-byte 0x hash")
        return self

    @property
    def is_pending(self) -> bool:
        """True for the non-terminal ``settlement_pending`` outcome (CORE §9)."""
        return not self.success and self.error_reason == "settlement_pending"


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
    #: CORE §8.3: an ISO 8601 timestamp string since x402#3067. The V1 shape, a
    #: non-negative Unix-seconds number, is still accepted because older
    #: facilitators send it; DI-001 reports it as an advisory, not a failure.
    last_updated: (
        Annotated[str, Field(min_length=1)]
        | Annotated[int, Field(ge=0)]
        | Annotated[FiniteFloat, Field(ge=0)]
    ) = Field(alias="lastUpdated")
    metadata: dict[str, Any] | None = None

    @field_validator("last_updated")
    @classmethod
    def validate_last_updated(cls, value: str | int | float) -> str | int | float:
        """A string `lastUpdated` must be a real ISO 8601 timestamp, not any text."""
        if isinstance(value, str) and not is_iso8601_timestamp(value):
            raise ValueError("lastUpdated must be an ISO 8601 timestamp")
        return value


class DiscoveryPagination(WireModel):
    limit: int = Field(ge=0)
    offset: int = Field(ge=0)
    total: int = Field(ge=0)


class DiscoveryResponse(WireModel):
    """CORE §8.1 discovery response envelope."""

    x402_version: int = Field(alias="x402Version")
    items: list[DiscoveryItem]
    pagination: DiscoveryPagination
