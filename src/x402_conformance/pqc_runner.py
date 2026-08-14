"""Public entry point for the explicitly selected PQC conformance profile."""

from __future__ import annotations

import httpx

from .checks.base import CheckResult
from .runner import run_checks


def run_pqc_checks(
    url: str,
    method: str = "GET",
    timeout: float = 10.0,
    transport: httpx.BaseTransport | None = None,
) -> list[CheckResult]:
    """Run only PQC-001..006; never selected by the default runner."""
    return run_checks(url, method=method, timeout=timeout, transport=transport, profile="pqc")
