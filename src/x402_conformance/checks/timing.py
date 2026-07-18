"""RS-SEC-008 — rejection-timing oracle (opt-in, advisory).

Two invalid payments that fail at *different* stages of validation should not be
distinguishable by how long the endpoint takes to reject them. If a
wrong-signature payment (fails at signature recovery, early) and a valid-signature
wrong-amount payment (recovery succeeds, then the amount check fails, later) come
back with markedly different timings, the endpoint leaks *which* check failed — a
side channel an attacker can probe to forge a payment step by step.

Timing is inherently noisy, so this check is:
  * **opt-in** (`check --timing`), never part of the default active run;
  * **MINOR / advisory** — it never gates the conformance verdict;
  * **conservative** — it flags only a gross, reproducible separation (median gap
    both above an absolute floor AND several times the within-class noise), so
    normal jitter can't produce a false positive.

The decision (:func:`classify_timing`) is pure and deterministic given samples;
the measurement clock is injected so it is unit-tested without real timing.
"""

from __future__ import annotations

import statistics
import time
from collections.abc import Callable
from typing import Any

from ..payload_builder import (
    build_exact_eip3009_payload,
    signature_recovers_to_authorizer,
    tamper_signature,
)
from .base import CheckResult, Severity, Status

_CORE = "x402-specification-v2.md"
TIMING_CHECK_ID = "RS-SEC-008"
_TITLE = "Rejection timing does not leak the rejection reason (timing oracle)"
_MIN_SAMPLES = 5


def _mad(xs: list[float]) -> float:
    """Median absolute deviation — a robust, outlier-resistant spread estimate."""
    m = statistics.median(xs)
    return statistics.median([abs(x - m) for x in xs])


def classify_timing(
    early: list[float], late: list[float], *, floor: float = 0.025, ratio: float = 4.0
) -> tuple[bool, str]:
    """Decide whether two rejection-timing samples reveal an oracle.

    Compares the class medians; flags only when their gap is BOTH >= ``floor``
    seconds (absolute) AND >= ``ratio`` times the within-class noise (MAD). Pure
    and deterministic.
    """
    me, ml = statistics.median(early), statistics.median(late)
    diff = abs(ml - me)
    noise = max(_mad(early), _mad(late))
    is_oracle = diff >= floor and diff >= ratio * max(noise, 1e-9)
    detail = (
        f"class-A median {me * 1000:.1f}ms, class-B median {ml * 1000:.1f}ms "
        f"(Δ {diff * 1000:.1f}ms, noise {noise * 1000:.1f}ms)"
    )
    return is_oracle, detail


def _result(status: Status, detail: str) -> CheckResult:
    return CheckResult(TIMING_CHECK_ID, _TITLE, Severity.MINOR, f"{_CORE} §10.1", status, detail)


def _sample(
    send: Callable[[dict[str, Any]], Any],
    payload: dict[str, Any],
    n: int,
    time_fn: Callable[[], float],
) -> list[float]:
    durations: list[float] = []
    for _ in range(n):
        t0 = time_fn()
        resp = send(payload)
        t1 = time_fn()
        # A dropped connection has no meaningful timing — skip that sample.
        if getattr(resp, "transport_error", None) is None:
            durations.append(t1 - t0)
    return durations


def evaluate_timing(
    context: Any,
    *,
    samples: int = 15,
    time_fn: Callable[[], float] = time.perf_counter,
) -> list[CheckResult]:
    """Probe the rejection-timing oracle. Returns a single RS-SEC-008 result.

    ``context is None`` yields a SKIP (so the ID is enumerable for the catalog
    count) — the real probe needs a live, payable endpoint and a signer.
    """
    if context is None:
        return [_result(Status.SKIP, "timing probe not run (opt-in via --timing)")]

    payload = build_exact_eip3009_payload(
        context.requirements,
        context.signer,
        resource_url=context.resource_url,
        extensions=context.extensions,
    )
    early = _sample(context.send, tamper_signature(payload), samples, time_fn)
    required = int(context.requirements["amount"])
    if required <= 1:
        return [_result(Status.SKIP, "cannot construct a positive underpayment sample")]
    cheap = {**context.requirements, "amount": str(max(1, required // 2))}
    late_payload = build_exact_eip3009_payload(
        cheap,
        context.signer,
        resource_url=context.resource_url,
        extensions=context.extensions,
    )
    assert signature_recovers_to_authorizer(late_payload, cheap)
    late_payload["accepted"] = dict(context.requirements)
    late = _sample(context.send, late_payload, samples, time_fn)
    if len(early) < _MIN_SAMPLES or len(late) < _MIN_SAMPLES:
        return [_result(Status.SKIP, "insufficient timing samples (endpoint unreachable/crashing)")]

    is_oracle, detail = classify_timing(early, late)
    if is_oracle:
        return [
            _result(
                Status.FAIL,
                "possible timing oracle: "
                + detail
                + " — rejection time reveals which check failed; make the reject path "
                "constant-time across reasons",
            )
        ]
    return [_result(Status.PASS, "no timing oracle detected: " + detail)]
