"""RS-HS: 402 handshake checks (catalog §1).

Passive checks on the unpaid request — no payment is ever made here.
"""

from __future__ import annotations

from ..probe import PAYMENT_REQUIRED_HEADER, ProbeSession
from .base import Severity, Status, register

_HTTP_REF = "transports-v2/http.md §Payment Required Signaling"


@register("RS-HS-001", "Unpaid request is answered with HTTP 402", Severity.MAJOR, _HTTP_REF)
def hs_001(s: ProbeSession) -> tuple[Status, str]:
    code = s.first.status_code
    if code == 402:
        return Status.PASS, ""
    if 200 <= code < 300:
        return Status.FAIL, (
            f"got {code}: endpoint served content without payment — "
            "either not x402-protected or paywall is broken"
        )
    return Status.FAIL, f"expected 402, got {code}"


@register("RS-HS-002", "402 response carries PAYMENT-REQUIRED header", Severity.MAJOR, _HTTP_REF)
def hs_002(s: ProbeSession) -> tuple[Status, str]:
    if s.first.status_code != 402:
        return Status.SKIP, "no 402 response to inspect"
    if s.first.header_b64 is None:
        return Status.FAIL, f"402 without {PAYMENT_REQUIRED_HEADER.upper()} header"
    return Status.PASS, ""


@register("RS-HS-003", "PAYMENT-REQUIRED header is valid base64", Severity.MAJOR, _HTTP_REF)
def hs_003(s: ProbeSession) -> tuple[Status, str]:
    if s.first.header_b64 is None:
        return Status.SKIP, "header not present"
    if s.first.decode_error is not None:
        return Status.FAIL, s.first.decode_error
    return Status.PASS, ""


@register(
    "RS-HS-004",
    "Decoded header is valid JSON matching the PaymentRequired schema",
    Severity.MAJOR,
    "x402-specification-v2.md §5.1",
)
def hs_004(s: ProbeSession) -> tuple[Status, str]:
    if s.first.decoded is None:
        return Status.SKIP, "nothing decodable"
    if s.first.json_error is not None:
        return Status.FAIL, s.first.json_error
    if s.first.parse_error is not None:
        return Status.FAIL, f"schema violation: {s.first.parse_error}"
    return Status.PASS, ""


@register(
    "RS-HS-005",
    "No deprecated legacy X-* payment headers in V2 response",
    Severity.MINOR,
    "transports-v2/http.md §Header Summary",
)
def hs_005(s: ProbeSession) -> tuple[Status, str]:
    legacy = s.first.legacy_headers_present
    if legacy:
        return Status.FAIL, (
            f"legacy header(s) present: {', '.join(legacy)} — "
            "V1 leftovers; V2 uses PAYMENT-REQUIRED/-SIGNATURE/-RESPONSE"
        )
    return Status.PASS, ""


@register(
    "RS-HS-006",
    "Protocol data complete via headers alone (body not required)",
    Severity.MINOR,
    "transports-v2/http.md §Response Body",
)
def hs_006(s: ProbeSession) -> tuple[Status, str]:
    if s.first.parsed is None:
        return Status.SKIP, "no parseable PaymentRequired header"
    # If the header parsed against the full schema, the client needs nothing
    # from the response body — which is exactly what the transport spec wants.
    return Status.PASS, ""


@register(
    "RS-HS-007",
    "402 with payment details is not cacheable",
    Severity.MAJOR,
    "RFC 9111 + testcase PR1",
)
def hs_007(s: ProbeSession) -> tuple[Status, str]:
    if s.first.status_code != 402:
        return Status.SKIP, "no 402 response to inspect"
    cache_control = s.first.headers.get("cache-control", "").lower()
    if not cache_control:
        # 402 is not heuristically cacheable by default (RFC 9111 §4.2.2), so
        # this is not a hard failure — but explicit no-store is best practice
        # so a CDN/proxy can never serve a stale paywall.
        return Status.PASS, "no Cache-Control header; explicit 'no-store' recommended"
    if "no-store" in cache_control or "private" in cache_control:
        return Status.PASS, ""
    if "public" in cache_control or _positive_max_age(cache_control):
        return Status.FAIL, (
            f"402 is actively cacheable (Cache-Control: {cache_control!r}) — "
            "a CDN/proxy could serve this paywall (and its payment details) to other clients"
        )
    return Status.PASS, ""


def _positive_max_age(cache_control: str) -> bool:
    for part in cache_control.split(","):
        part = part.strip()
        if part.startswith("max-age=") or part.startswith("s-maxage="):
            value = part.split("=", 1)[1].strip()
            if value.isdigit() and int(value) > 0:
                return True
    return False
