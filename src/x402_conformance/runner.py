"""Run all registered checks against a target endpoint."""

from __future__ import annotations

import httpx

from .checks import REGISTRY, CheckResult, Status
from .probe import ProbeSession, build_probe

USER_AGENT = "x402-conformance/0.1.0 (+https://github.com/x402-conformance)"


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
    with httpx.Client(
        timeout=timeout, transport=transport, follow_redirects=True, headers=headers
    ) as client:
        first = build_probe(client.request(method, url))
        second = build_probe(client.request(method, url))

    session = ProbeSession(target_url=url, method=method, first=first, second=second)

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
