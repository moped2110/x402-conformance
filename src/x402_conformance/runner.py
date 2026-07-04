"""Run all registered checks against a target endpoint."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from .checks import REGISTRY, CheckResult, Status
from .jp402 import find_jp402
from .probe import PAYMENT_REQUIRED_HEADER, Probe, ProbeSession, build_probe

USER_AGENT = "x402-conformance/0.1.0 (+https://github.com/x402-conformance)"


def _is_paywall(p: Probe) -> bool:
    """Looks like an x402 handshake: a 402 status or a PAYMENT-REQUIRED header."""
    return p.status_code == 402 or PAYMENT_REQUIRED_HEADER in p.headers


def _maybe_fetch_openapi(
    client: httpx.Client, target_url: str, first: Probe
) -> dict[str, Any] | None:
    """Fetch ``{origin}/openapi.json`` — but only when the live 402 advertises
    ``jp402``, so a non-JP endpoint never incurs the extra request. Returns the
    parsed doc, or ``None`` if not applicable / unreachable / not a JSON object.
    """
    if first.raw is None or find_jp402(first.raw) is None:
        return None
    parts = urlsplit(target_url)
    if not parts.scheme or not parts.netloc:
        return None
    openapi_url = urlunsplit((parts.scheme, parts.netloc, "/openapi.json", "", ""))
    try:
        resp = client.request("GET", openapi_url)
        if resp.status_code != 200:
            return None
        doc = json.loads(resp.text)
    except Exception:
        return None
    return doc if isinstance(doc, dict) else None


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
        first = build_probe(client.request(method, url))
        effective = method
        # A POST-only (or GET-only) endpoint answers the wrong verb with 404/405. If the
        # *other* verb reveals a real x402 paywall, adopt it — so a POST-gated resource
        # isn't a false negative. Otherwise keep the original response so the handshake
        # checks report it faithfully (a genuine non-402 is still a finding).
        if not _is_paywall(first) and first.status_code in (404, 405):
            alt = "POST" if method.upper() == "GET" else "GET"
            alt_probe = build_probe(client.request(alt, url))
            if _is_paywall(alt_probe):
                notes.append(
                    f"auto-switched method {method.upper()}->{alt}: {method.upper()} "
                    f"returned {first.status_code}, {alt} reveals an x402 paywall"
                )
                first, effective = alt_probe, alt
        second = build_probe(client.request(effective, url))
        openapi = _maybe_fetch_openapi(client, url, first)

    session = ProbeSession(
        target_url=url, method=effective, first=first, second=second,
        openapi=openapi, notes=notes,
    )

    results: list[CheckResult] = []
    for check in REGISTRY:
        try:
            status, detail = check.func(session)
        except Exception as exc:  # a crashing check is OUR bug, never the target's
            status, detail = Status.ERROR, f"check crashed (suite bug): {exc!r}"
        results.append(
            CheckResult(
                check_id=check.check_id,
                title=check.title,
                severity=check.severity,
                spec_ref=check.spec_ref,
                status=status,
                detail=detail,
            )
        )
    return results
