"""Probing: perform unpaid requests and pre-digest the response for checks.

A ``Probe`` captures everything checks need: status code, headers, and the
staged decoding of the PAYMENT-REQUIRED header (base64 -> JSON -> schema).
Each stage records its error instead of raising, so checks can report the
exact failure layer (RS-HS-003 vs -004 etc.).
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass, field

import httpx
from pydantic import ValidationError

from .models import PaymentRequired

PAYMENT_REQUIRED_HEADER = "payment-required"
LEGACY_HEADERS = ("x-payment", "x-payment-required", "x-payment-response")


@dataclass(frozen=True)
class Probe:
    """One unpaid request/response, pre-digested."""

    status_code: int
    headers: dict[str, str]
    body: bytes
    header_b64: str | None = None
    decoded: bytes | None = None
    decode_error: str | None = None
    raw: dict[str, object] | None = None
    json_error: str | None = None
    parsed: PaymentRequired | None = None
    parse_error: str | None = None

    @property
    def legacy_headers_present(self) -> list[str]:
        return [h for h in LEGACY_HEADERS if h in self.headers]


@dataclass(frozen=True)
class ProbeSession:
    """All probes against one target; input to every check."""

    target_url: str
    method: str
    first: Probe
    second: Probe | None = None
    notes: list[str] = field(default_factory=list)


def build_probe(response: httpx.Response) -> Probe:
    headers = {k.lower(): v for k, v in response.headers.items()}
    header_b64 = headers.get(PAYMENT_REQUIRED_HEADER)

    decoded: bytes | None = None
    decode_error: str | None = None
    raw: dict[str, object] | None = None
    json_error: str | None = None
    parsed: PaymentRequired | None = None
    parse_error: str | None = None

    if header_b64 is not None:
        try:
            decoded = base64.b64decode(header_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            decode_error = f"invalid base64: {exc}"

    if decoded is not None:
        try:
            loaded = json.loads(decoded)
            if isinstance(loaded, dict):
                raw = loaded
            else:
                json_error = f"top-level JSON is {type(loaded).__name__}, expected object"
        except json.JSONDecodeError as exc:
            json_error = f"invalid JSON: {exc}"

    if raw is not None:
        try:
            parsed = PaymentRequired.model_validate(raw)
        except ValidationError as exc:
            parse_error = "; ".join(
                f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}" for err in exc.errors()
            )

    return Probe(
        status_code=response.status_code,
        headers=headers,
        body=response.content,
        header_b64=header_b64,
        decoded=decoded,
        decode_error=decode_error,
        raw=raw,
        json_error=json_error,
        parsed=parsed,
        parse_error=parse_error,
    )
