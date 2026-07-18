"""Run all registered checks against a target endpoint."""

from __future__ import annotations

import json
import time
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from . import USER_AGENT

# Reuse the active runner's transient-fault policy so passive and active probing
# treat flaky infra identically (429/502/503/504 + a sane Retry-After).
from .active import _MAX_RETRIES, _TRANSIENT_STATUS, _retry_delay
from .checks import REGISTRY, CheckResult, Status
from .jp402 import find_jp402
from .probe import PAYMENT_REQUIRED_HEADER, Probe, ProbeSession, build_probe


class EndpointUnreachable(httpx.HTTPError):
    """The endpoint answered only with a server error (5xx) and no x402 paywall
    signal. That is an infrastructure failure, not a payment verdict, so we treat
    it like a connection failure — the run is inconclusive (exit 2), never a
    conformance FAIL. Subclasses ``httpx.HTTPError`` so the CLI's existing
    unreachable path records and exits on it without special-casing."""


def _is_paywall(p: Probe) -> bool:
    """Looks like an x402 handshake: a 402 status or a PAYMENT-REQUIRED header."""
    return p.status_code == 402 or PAYMENT_REQUIRED_HEADER in p.headers


def _unreachable_reason(p: Probe) -> str | None:
    """A 5xx with no x402 paywall signal means the endpoint is down/broken at the
    infra layer — inconclusive, not a conformance verdict. A 5xx that still carries
    a paywall signal is left to the checks (an odd but on-protocol response)."""
    if p.status_code >= 500 and not _is_paywall(p):
        return f"endpoint returned server error HTTP {p.status_code} with no x402 paywall signal"
    return None


def _request_with_transient_retry(client: httpx.Client, method: str, url: str) -> httpx.Response:
    """One unpaid request, retrying only *transient* statuses (429/502/503/504) a
    few times — a rate-limit or cold-start blip shouldn't be read as a down endpoint.
    A persistent 5xx (e.g. 500/530) is returned as-is for the caller to classify.
    Connection-level errors propagate unchanged (the CLI records them as unreachable)."""
    resp = client.request(method, url)
    attempt = 0
    while resp.status_code in _TRANSIENT_STATUS and attempt < _MAX_RETRIES:
        time.sleep(_retry_delay(resp, attempt))
        resp = client.request(method, url)
        attempt += 1
    return resp


def _maybe_fetch_openapi(
    client: httpx.Client, target_url: str, first: Probe
) -> tuple[dict[str, Any] | None, str | None]:
    """Fetch ``{origin}/openapi.json`` — but only when the live 402 advertises
    ``jp402``, so a non-JP endpoint never incurs the extra request.

    Returns ``(doc, reason)``. On success ``(doc, None)``. When a JP402 endpoint
    was advertised but the doc couldn't be obtained, ``doc`` is ``None`` and
    ``reason`` is a short diagnostic (timeout vs 404 vs not-JSON) so a swallowed
    failure surfaces in the report instead of looking like "no openapi advertised".
    A non-JP endpoint returns ``(None, None)`` — nothing was attempted, no note.
    """
    if first.raw is None or find_jp402(first.raw) is None:
        return None, None
    parts = urlsplit(target_url)
    if not parts.scheme or not parts.netloc:
        return None, "jp402 advertised but target URL has no scheme/host to derive /openapi.json"
    openapi_url = urlunsplit((parts.scheme, parts.netloc, "/openapi.json", "", ""))
    try:
        resp = client.request("GET", openapi_url)
    except httpx.HTTPError as exc:
        return None, f"jp402 advertised but /openapi.json unreachable: {type(exc).__name__}"
    if resp.status_code != 200:
        return None, f"jp402 advertised but /openapi.json returned HTTP {resp.status_code}"
    try:
        doc = json.loads(resp.text)
    except (ValueError, UnicodeDecodeError) as exc:
        return None, f"jp402 advertised but /openapi.json is not valid JSON: {type(exc).__name__}"
    if not isinstance(doc, dict):
        return None, "jp402 advertised but /openapi.json is not a JSON object"
    return doc, None


def run_checks(
    url: str,
    method: str = "GET",
    timeout: float = 10.0,
    transport: httpx.BaseTransport | None = None,
) -> list[CheckResult]:
    """Probe ``url`` (two unpaid requests) and evaluate every registered check.

    ``transport`` is injectable for offline testing (httpx.MockTransport).
    """
    headers = {"User-Agent": USER_AGENT}
    notes: list[str] = []
    with httpx.Client(
        timeout=timeout, transport=transport, follow_redirects=True, headers=headers
    ) as client:
        first = build_probe(_request_with_transient_retry(client, method, url))
        # Never change the operator-selected method: switching GET to POST can
        # trigger application side effects. Rerun with an explicit `--method`.
        effective = method
        # A persistent server error with no paywall signal is unreachable, not a
        # FAIL — bail before further probing so the run is recorded as inconclusive.
        reason = _unreachable_reason(first)
        if reason is not None:
            raise EndpointUnreachable(reason)
        second = build_probe(_request_with_transient_retry(client, effective, url))
        openapi, openapi_reason = _maybe_fetch_openapi(client, url, first)
        if openapi_reason is not None:
            notes.append(openapi_reason)

    session = ProbeSession(
        target_url=url,
        method=effective,
        first=first,
        second=second,
        openapi=openapi,
        notes=notes,
    )

    results: list[CheckResult] = []
    for check in REGISTRY:
        try:
            # A check returns (status, detail) or (status, detail, reason_code); the
            # star capture normalises both without the runner caring which it used.
            status, detail, *rest = check.func(session)
        except Exception as exc:  # a crashing check is OUR bug, never the target's
            status, detail, rest = Status.ERROR, f"check crashed (suite bug): {exc!r}", []
        results.append(
            CheckResult(
                check_id=check.check_id,
                title=check.title,
                severity=check.severity,
                spec_ref=check.spec_ref,
                status=status,
                detail=detail,
                reason_code=rest[0] if rest else None,
            )
        )
    return results
