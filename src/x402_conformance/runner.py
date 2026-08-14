"""Run all registered checks against a target endpoint."""

from __future__ import annotations

import copy
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
from .checks.path_variants import PathVariant, build_variants
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


def _probe_path_variants(
    client: httpx.Client,
    url: str,
    method: str,
    first: Probe,
    resource_marker: str | None,
) -> tuple[list[tuple[PathVariant, int | None, bool]] | None, dict[str, bool] | None]:
    """Request the target again under re-encoded paths, for RS-SEC-012.

    Only runs when the canonical request actually produced a paywall — with no
    402 there is nothing to bypass, and probing an open endpoint's path variants
    would just be noise. Transport failures are recorded as "not served" rather
    than raised: one unreachable variant must not sink the whole run.
    """
    if not _is_paywall(first):
        return None, None
    variants = build_variants(url)
    if not variants:
        return None, None
    outcomes: list[tuple[PathVariant, int | None, bool]] = []
    marker_seen: dict[str, bool] | None = {} if resource_marker else None
    for variant in variants:
        try:
            resp = client.request(method, variant.url)
        except httpx.HTTPError:
            outcomes.append((variant, None, False))
            continue
        body = resp.text or ""
        outcomes.append((variant, resp.status_code, bool(body.strip())))
        if marker_seen is not None and resource_marker is not None:
            marker_seen[variant.label] = resource_marker in body
    return outcomes, marker_seen


def run_checks(
    url: str,
    method: str = "GET",
    timeout: float = 10.0,
    transport: httpx.BaseTransport | None = None,
    resource_marker: str | None = None,
    profile: str | None = None,
) -> list[CheckResult]:
    """Probe ``url`` (two unpaid requests) and evaluate every registered check.

    ``transport`` is injectable for offline testing (httpx.MockTransport).
    ``resource_marker`` is a distinctive string from the protected content; when
    given, RS-SEC-012 only calls a re-encoded path a bypass if the marker is
    actually in the served body.
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
        path_variants, variant_marker = _probe_path_variants(
            client, url, effective, first, resource_marker
        )
        pqc_tamper_response: dict[str, object] | None = None
        pqc_downgrade_response: dict[str, object] | None = None
        if profile == "pqc":
            pqc_tamper_response, pqc_downgrade_response = _probe_pqc_verifier(client, first)

    session = ProbeSession(
        target_url=url,
        method=effective,
        first=first,
        second=second,
        openapi=openapi,
        notes=notes,
        path_variants=path_variants,
        path_variant_marker=variant_marker,
        pqc_tamper_response=pqc_tamper_response,
        pqc_downgrade_response=pqc_downgrade_response,
    )

    results: list[CheckResult] = []
    if profile == "pqc":
        from .checks.pqc import PQC_REGISTRY

        selected_checks = PQC_REGISTRY
    else:
        selected_checks = REGISTRY
    for check in selected_checks:
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


def _probe_pqc_verifier(
    client: httpx.Client, first: Probe
) -> tuple[dict[str, object] | None, dict[str, object] | None]:
    """Send the two safe, invalid-receipt probes required by the PQC profile."""
    raw = first.raw
    extensions = raw.get("extensions") if isinstance(raw, dict) else None
    capability = extensions.get("pqc") if isinstance(extensions, dict) else None
    if not isinstance(capability, dict):
        return None, None
    receipt = capability.get("receipt")
    verify_url = capability.get("verifyUrl")
    if not isinstance(receipt, dict) or not isinstance(verify_url, str):
        return None, None

    tampered = copy.deepcopy(receipt)
    sig_v2 = tampered.get("sig_v2")
    if not isinstance(sig_v2, dict):
        return None, None
    pqc = sig_v2.get("pqc")
    if not isinstance(pqc, dict) or not isinstance(pqc.get("signature"), str):
        return None, None
    signature = str(pqc["signature"])
    pqc["signature"] = ("A" if not signature.startswith("A") else "B") + signature[1:]
    stripped = copy.deepcopy(receipt)
    stripped.pop("sig_v2", None)

    def post(value: dict[str, object]) -> dict[str, object] | None:
        try:
            response = client.post(verify_url, json=value, follow_redirects=False)
            decoded = response.json()
        except (httpx.HTTPError, ValueError, UnicodeDecodeError):
            return None
        return decoded if isinstance(decoded, dict) else None

    return post(tampered), post(stripped)
