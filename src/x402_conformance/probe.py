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
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import httpx
from pydantic import ValidationError

from .models import PaymentRequired

PAYMENT_REQUIRED_HEADER = "payment-required"
LEGACY_HEADERS = ("x-payment", "x-payment-required", "x-payment-response")

#: Path suffixes that mark a facilitator/discovery endpoint rather than a paywalled
#: resource. A facilitator's ``/supported`` correctly answers 200, not 402, so a
#: passive resource ``check`` aimed at one would otherwise read as a false RS-HS-001.
_FACILITATOR_PATH_SUFFIXES = ("/supported", "/verify", "/settle")
_DISCOVERY_PATH = ".well-known/x402"


def facilitator_path_kind(url: str) -> str | None:
    """Classify a URL as a facilitator/discovery endpoint, or None for a resource.

    Returns the matched marker (``.well-known/x402`` or one of the facilitator path
    suffixes) so callers can name it; a normal paywalled-resource URL returns None.
    The single source of truth for both the CLI hint and RS-HS-001's guard, so the
    two cannot disagree about what counts as "not a resource".
    """
    path = urlsplit(url).path.lower().rstrip("/")
    if path.endswith(f"/{_DISCOVERY_PATH}"):
        return _DISCOVERY_PATH
    for suffix in _FACILITATOR_PATH_SUFFIXES:
        if path.endswith(suffix):
            return suffix
    return None


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
    # Findings about the JSON *text*, recorded while decoding rather than inferred
    # afterwards: once the document is a dict, a duplicate key and a JSON literal
    # that RFC 8259 does not define are both invisible.
    nonstandard_json_literals: tuple[str, ...] = ()
    duplicate_json_keys: tuple[str, ...] = ()

    @property
    def legacy_headers_present(self) -> list[str]:
        """List deprecated x402 V1 payment headers present on the response."""
        return [h for h in LEGACY_HEADERS if h in self.headers]


@dataclass(frozen=True)
class ProbeSession:
    """All probes against one target; input to every check.

    ``openapi`` is the target's parsed ``/openapi.json`` document, fetched by the
    runner *only* when the live 402 advertises ``jp402`` (the JP-rail extension) —
    the discovery surface where the qualified-invoice metadata lives. ``None`` for
    every non-JP endpoint, so no extra request is made in the common case.
    """

    target_url: str
    method: str
    first: Probe
    second: Probe | None = None
    openapi: dict[str, object] | None = None
    notes: list[str] = field(default_factory=list)


# A PaymentRequired challenge travels base64-encoded in an HTTP response header, so
# the HTTP layer already bounds it. This is a second bound on the decoded bytes:
# cheap, and it makes an oversized challenge a refusal rather than a parse.
_MAX_CHALLENGE_BYTES = 256 * 1024


_JsonFindings = dict[str, list[str]]
_ParseConstant = Callable[[str], float]
_ObjectPairsHook = Callable[[list[tuple[str, object]]], dict[str, object]]


def _collect_json_findings() -> tuple[_JsonFindings, _ParseConstant, _ObjectPairsHook]:
    """Build the two json.loads hooks and the record they write into.

    Both hooks preserve the default behaviour exactly — the same dict comes out with
    the same values — and only note what the text contained on the way past. The
    parse must not change: every other check reads the parsed document, and a
    stricter parser here would silently alter their input.
    """
    found: _JsonFindings = {"literals": [], "duplicates": []}
    constants = {"NaN": float("nan"), "Infinity": float("inf"), "-Infinity": float("-inf")}

    def parse_constant(name: str) -> float:
        """Record a non-RFC-8259 literal and return what json would have returned."""
        if name not in found["literals"]:
            found["literals"].append(name)
        return constants.get(name, float("nan"))

    def object_pairs_hook(pairs: list[tuple[str, object]]) -> dict[str, object]:
        """Record repeated keys, then collapse last-wins exactly as json does."""
        seen: set[str] = set()
        for key, _value in pairs:
            if key in seen and key not in found["duplicates"]:
                found["duplicates"].append(key)
            seen.add(key)
        return dict(pairs)

    return found, parse_constant, object_pairs_hook


def build_probe(response: httpx.Response) -> Probe:
    """Stage base64, JSON, and strict schema parsing without raising on hostile input."""
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

    findings, parse_constant, object_pairs_hook = _collect_json_findings()

    if decoded is not None and len(decoded) > _MAX_CHALLENGE_BYTES:
        json_error = (
            f"challenge is {len(decoded)} bytes, over the {_MAX_CHALLENGE_BYTES}-byte "
            "limit — not parsed"
        )
    elif decoded is not None:
        try:
            loaded = json.loads(
                decoded, parse_constant=parse_constant, object_pairs_hook=object_pairs_hook
            )
            if isinstance(loaded, dict):
                raw = loaded
            else:
                json_error = f"top-level JSON is {type(loaded).__name__}, expected object"
        except json.JSONDecodeError as exc:
            json_error = f"invalid JSON: {exc}"
        except RecursionError:
            # Deeply nested input exhausts the decoder's stack. That is a crash on
            # hostile input, which SECURITY.md puts in scope — and a header carrying
            # a thousand open brackets is under a kilobyte.
            json_error = "JSON nesting is too deep to parse"

    if raw is not None:
        try:
            parsed = PaymentRequired.model_validate(raw)
        except ValidationError as exc:
            parse_error = "; ".join(
                f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}" for err in exc.errors()
            )

    return Probe(
        nonstandard_json_literals=tuple(findings["literals"]),
        duplicate_json_keys=tuple(findings["duplicates"]),
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
