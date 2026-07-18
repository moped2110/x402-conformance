"""Active probing: send (tampered) payments and observe the endpoint's response.

Passive checks (RS-HS/RS-PR) only do unpaid GETs. The negative group (RS-NEG)
must actively construct payments and verify the endpoint *rejects* the invalid
ones. This module provides that capability, kept separate from the passive
runner so the default behaviour never sends a payment without explicit intent.

Active checks require the `[evm]` extra (signing) and a throwaway signer.
"""

from __future__ import annotations

import base64
import copy
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Any

import httpx

from . import USER_AGENT
from .models import SettlementResponse
from .probe import build_probe
from .safety import DEFAULT_SAFETY_POLICY, SafetyPolicy, SafetyViolation

PAYMENT_SIGNATURE_HEADER = "PAYMENT-SIGNATURE"
PAYMENT_RESPONSE_HEADER = "payment-response"

# --- transient-fault retry ---------------------------------------------------
# A conformance run may cross flaky infra (load balancers, rate limiters, cold
# starts). These faults are transient and NOT a verdict on the payment, so a
# real x402 client retries them; we mirror that so a hiccup doesn't turn into a
# spurious finding. A *deterministic* fault still reproduces on every retry and
# is reported unchanged — retrying only smooths over genuine transients.
#
# 429 = backpressure/rate-limit; 502/503/504 = transient upstream fault.
_TRANSIENT_STATUS = frozenset({429, 502, 503, 504})
# Connection-level faults worth a retry (network blip / pool timeout). A
# non-retryable httpx error (e.g. RemoteProtocolError — the endpoint broke the
# connection mid-response) is surfaced immediately as an endpoint fault instead.
_RETRYABLE_ERRORS = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.ReadTimeout,
    httpx.WriteTimeout,
    httpx.PoolTimeout,
)
_MAX_RETRIES = 2  # up to 3 attempts total
_RETRY_BACKOFF = 0.5  # seconds; doubled each attempt
_RETRY_AFTER_CAP = 30.0  # never let a hostile Retry-After stall the run past this


def _retry_delay(response: httpx.Response, attempt: int) -> float:
    """Seconds to wait before the next attempt. Honour a numeric ``Retry-After``
    (delta-seconds) when present and sane; otherwise exponential backoff. The
    HTTP-date form of Retry-After is ignored (falls back to backoff), and any
    value is capped so a server can't park us indefinitely."""
    raw = response.headers.get("Retry-After")
    if raw is not None:
        try:
            return max(0.0, min(float(int(raw)), _RETRY_AFTER_CAP))
        except ValueError:
            pass
    return float(_RETRY_BACKOFF * (2**attempt))


@dataclass(frozen=True)
class ActiveResponse:
    """The endpoint's response to a (tampered) payment attempt."""

    status_code: int
    headers: dict[str, str]
    body: bytes
    settlement: SettlementResponse | None = None
    settlement_error: str | None = None
    marker_leaked: bool = False  # resource_marker found in body (content leak)
    # Set when the request could not complete because the ENDPOINT broke the
    # connection (reset / protocol error / no response). That's the target crashing
    # on our input — an endpoint fault, never a suite bug. status_code is 0 then.
    transport_error: str | None = None
    # Set for a payment-bearing 3xx response.  The client never follows it and
    # deliberately does not copy the Location value into reports (it may contain
    # credentials).  Status alone is enough to identify the blocked redirect.
    redirect_blocked: str | None = None

    @property
    def served_resource(self) -> bool:
        """True if the endpoint delivered content (2xx) — i.e. accepted the payment."""
        return self.transport_error is None and 200 <= self.status_code < 300

    @property
    def endpoint_crashed(self) -> bool:
        """The endpoint failed to answer cleanly: a 5xx, or it dropped/reset the
        connection (transport error). Robustness checks treat this as a FAIL of the
        endpoint — it must not crash on hostile-but-well-formed input."""
        return self.transport_error is not None or self.status_code >= 500

    @property
    def settled_ok(self) -> bool:
        """Report whether the parsed settlement response explicitly records success."""
        return self.settlement is not None and self.settlement.success


@dataclass
class ActiveContext:
    """Everything an active check needs to attack one endpoint."""

    resource_url: str
    method: str
    requirements: dict[str, Any]  # chosen exact/eip3009 accepts entry
    extensions: dict[str, Any]  # server extension metadata echoed into PaymentPayload
    signer: Any  # EvmSigner
    send: Callable[[dict[str, Any]], ActiveResponse]
    send_header: Callable[[str], ActiveResponse]  # send a raw PAYMENT-SIGNATURE value
    # send a payload plus arbitrary extra headers (e.g. a contradictory legacy V1
    # X-PAYMENT header for the header-smuggling check, RS-SEC-006)
    send_with_headers: Callable[[dict[str, Any], dict[str, str]], ActiveResponse]
    resource_marker: str | None = None  # if set, a rejected body must NOT contain it
    notes: list[str] = field(default_factory=list)


def _b64_json(obj: dict[str, Any]) -> str:
    """Serialize a payment payload as compact JSON wrapped in base64 for the HTTP header."""
    return base64.b64encode(json.dumps(obj).encode()).decode()


def parse_settlement(headers: dict[str, str]) -> tuple[SettlementResponse | None, str | None]:
    """Decode and strictly validate an optional PAYMENT-RESPONSE header."""
    raw = headers.get(PAYMENT_RESPONSE_HEADER)
    if raw is None:
        return None, None
    try:
        decoded = base64.b64decode(raw, validate=True)
        data = json.loads(decoded)
        return SettlementResponse.model_validate(data), None
    except Exception as exc:  # malformed settlement header is itself a finding
        return None, f"unparseable PAYMENT-RESPONSE: {exc}"


def choose_eip3009_requirement(
    raw: dict[str, Any] | None,
    safety_policy: SafetyPolicy = DEFAULT_SAFETY_POLICY,
) -> dict[str, Any] | None:
    """Pick a safe ``exact``/EIP-3009 requirement.

    Eligible mainnet and unknown-chain entries fail closed instead of being
    silently skipped.  If a server advertises several eligible entries, a safe
    testnet/local entry is preferred.
    """
    if not raw:
        return None
    accepts = raw.get("accepts")
    if not isinstance(accepts, list):
        return None
    denied_networks: list[object] = []
    for entry in accepts:
        if not isinstance(entry, dict):
            continue
        if entry.get("scheme") != "exact":
            continue
        network = entry.get("network")
        if not (isinstance(network, str) and network.startswith("eip155:")):
            continue
        raw_extra = entry.get("extra")
        extra: dict[str, Any] = raw_extra if isinstance(raw_extra, dict) else {}
        if extra.get("assetTransferMethod", "eip3009") != "eip3009":
            continue
        if extra.get("name") and extra.get("version"):
            try:
                safety_policy.require_safe_network(network)
            except SafetyViolation:
                denied_networks.append(network)
                continue
            return entry
    if denied_networks:
        # Re-run the central policy to emit its stable, user-facing reason.
        safety_policy.require_safe_network(denied_networks[0])
    return None


def _response_from(response: httpx.Response) -> ActiveResponse:
    """Normalize an HTTP response and its settlement header into an active-check response."""
    headers = {k.lower(): v for k, v in response.headers.items()}
    settlement, settlement_error = parse_settlement(headers)
    redirect = (
        f"payment redirect blocked (HTTP {response.status_code})"
        if response.status_code in {301, 302, 303, 307, 308}
        else None
    )
    return ActiveResponse(
        status_code=response.status_code,
        headers=headers,
        body=response.content,
        settlement=settlement,
        settlement_error=settlement_error,
        redirect_blocked=redirect,
    )


def build_active_context(
    client: httpx.Client,
    url: str,
    method: str,
    signer: Any,
    resource_marker: str | None = None,
) -> ActiveContext | None:
    """Probe the endpoint for requirements and wire up payment senders.

    Returns None if the endpoint offers no exact/eip3009 requirement we can pay,
    or if the initial probe can't complete (unreachable / connection reset) — in
    both cases the active/pay checks SKIP cleanly instead of the tool crashing.
    """
    try:
        probe = build_probe(client.request(method, url, follow_redirects=False))
    except httpx.HTTPError:
        return None
    requirements = choose_eip3009_requirement(probe.raw)
    if requirements is None:
        return None
    extensions_raw = probe.raw.get("extensions") if probe.raw is not None else None
    extensions = copy.deepcopy(extensions_raw) if isinstance(extensions_raw, dict) else {}

    marker_bytes = resource_marker.encode() if resource_marker else None

    def _do(headers: dict[str, str]) -> ActiveResponse:
        """Send a payment-bearing request with bounded transient retries and content-leak detection."""
        transport_err: str | None = None
        for attempt in range(_MAX_RETRIES + 1):
            try:
                response = client.request(method, url, headers=headers, follow_redirects=False)
            except _RETRYABLE_ERRORS as exc:
                # Transient network fault — retry with backoff before giving up.
                transport_err = type(exc).__name__
                if attempt < _MAX_RETRIES:
                    time.sleep(_RETRY_BACKOFF * (2**attempt))
                    continue
                break
            except httpx.HTTPError as exc:
                # Non-retryable: the endpoint dropped/reset the connection (or
                # protocol-errored) on our input. That's the TARGET crashing, not our
                # bug — surface it as an endpoint fault so robustness checks report a
                # FAIL, not a suite ERROR.
                return ActiveResponse(
                    status_code=0, headers={}, body=b"", transport_error=type(exc).__name__
                )
            if response.status_code in _TRANSIENT_STATUS and attempt < _MAX_RETRIES:
                # Backpressure / transient upstream fault — wait and retry. If it
                # persists through all attempts we fall through and report it as-is
                # (a permanently-5xx endpoint is still a real fault).
                time.sleep(_retry_delay(response, attempt))
                continue
            ar = _response_from(response)
            if marker_bytes and marker_bytes in ar.body:
                ar = replace(ar, marker_leaked=True)
            return ar
        # Retries on a connection-level fault exhausted → report the endpoint fault.
        return ActiveResponse(status_code=0, headers={}, body=b"", transport_error=transport_err)

    def send(payload: dict[str, Any]) -> ActiveResponse:
        """Encode and send a structured payment payload."""
        return _do({PAYMENT_SIGNATURE_HEADER: _b64_json(payload)})

    def send_header(header_value: str) -> ActiveResponse:
        """Send an exact caller-supplied PAYMENT-SIGNATURE header value."""
        return _do({PAYMENT_SIGNATURE_HEADER: header_value})

    def send_with_headers(payload: dict[str, Any], extra: dict[str, str]) -> ActiveResponse:
        """Send a payment payload together with additional adversarial headers."""
        return _do({PAYMENT_SIGNATURE_HEADER: _b64_json(payload), **extra})

    return ActiveContext(
        resource_url=url,
        method=method,
        requirements=requirements,
        extensions=extensions,
        signer=signer,
        send=send,
        send_header=send_header,
        send_with_headers=send_with_headers,
        resource_marker=resource_marker,
    )


def preflight_resource_network(
    url: str,
    *,
    method: str = "GET",
    timeout: float = 10.0,
    rpc_url: str | None = None,
    require_rpc: bool = False,
    transport: httpx.BaseTransport | None = None,
    safety_policy: SafetyPolicy = DEFAULT_SAFETY_POLICY,
) -> str | None:
    """Validate the advertised network before CLI signer creation.

    The active runners repeat this check against the requirements they actually
    use, protecting both the CLI and direct library callers from a challenge that
    changes between requests.
    """

    with httpx.Client(
        timeout=timeout,
        transport=transport,
        follow_redirects=False,
        headers={"User-Agent": USER_AGENT},
    ) as client:
        probe = build_probe(client.request(method, url, follow_redirects=False))
    requirements = choose_eip3009_requirement(probe.raw, safety_policy)
    if requirements is None:
        return None
    network = safety_policy.require_safe_network(requirements.get("network"))
    if require_rpc:
        safety_policy.require_matching_rpc(network, rpc_url)
    return network


def run_active_checks(
    url: str,
    signer: Any,
    method: str = "GET",
    timeout: float = 10.0,
    transport: httpx.BaseTransport | None = None,
    resource_marker: str | None = None,
    concurrency: int = 1,
    progress: Callable[[Any, int, int], None] | None = None,
) -> list[Any]:
    """Run the RS-NEG active checks against `url`. Returns list[CheckResult].

    ``concurrency`` > 1 runs the checks on a thread pool; default 1 is sequential.
    ``progress`` is an optional ``(result, done, total)`` UI callback.
    """
    from .checks.negative import evaluate_active  # late import avoids cycle

    headers = {"User-Agent": USER_AGENT}
    with httpx.Client(
        timeout=timeout, transport=transport, follow_redirects=False, headers=headers
    ) as client:
        context = build_active_context(client, url, method, signer, resource_marker)
        return evaluate_active(context, concurrency=concurrency, progress=progress)


def run_timing_checks(
    url: str,
    signer: Any,
    method: str = "GET",
    timeout: float = 10.0,
    transport: httpx.BaseTransport | None = None,
    samples: int = 15,
) -> list[Any]:
    """Run the opt-in RS-SEC-008 timing-oracle probe. Returns list[CheckResult]."""
    from .checks.timing import evaluate_timing

    headers = {"User-Agent": USER_AGENT}
    with httpx.Client(
        timeout=timeout, transport=transport, follow_redirects=False, headers=headers
    ) as client:
        context = build_active_context(client, url, method, signer)
        return evaluate_timing(context, samples=samples)


def run_payment_checks(
    url: str,
    signer: Any,
    rpc_url: str | None = None,
    method: str = "GET",
    timeout: float = 30.0,
    transport: httpx.BaseTransport | None = None,
) -> list[Any]:
    """Run the RS-PAY positive settlement checks. MOVES REAL FUNDS — needs a
    funded signer. Returns list[CheckResult]."""
    from .checks.payment import PAY_CHECK_IDS, evaluate_payment

    headers = {"User-Agent": USER_AGENT}
    with httpx.Client(
        timeout=timeout, transport=transport, follow_redirects=False, headers=headers
    ) as client:
        context = build_active_context(client, url, method, signer)
        try:
            if context is not None:
                DEFAULT_SAFETY_POLICY.require_matching_rpc(
                    context.requirements.get("network"), rpc_url
                )
            return evaluate_payment(context, rpc_url)
        except Exception as exc:  # group-level net: parity with the registry groups
            # RS-PAY is a single linear settlement flow, not a registry loop, so it
            # has no per-check try/except. An unexpected crash here is OUR bug — turn
            # it into ERROR results for every RS-PAY id, never a hard tool crash.
            from .checks.base import CheckResult, Severity, Status

            detail = f"check crashed (suite bug): {exc!r}"
            return [
                CheckResult(
                    cid, cid, Severity.CRITICAL, "x402-specification-v2.md", Status.ERROR, detail
                )
                for cid in PAY_CHECK_IDS
            ]
