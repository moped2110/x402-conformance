"""RS-SEC-008 timing-oracle probe — deterministic decision + scripted-clock probe.

Timing is noisy in the wild, so the *decision* is a pure function of the samples
and the *measurement* clock is injected — both are tested without any real timing.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from x402_conformance.checks import Status
from x402_conformance.checks.timing import TIMING_CHECK_ID, classify_timing, evaluate_timing

# ------------------------------------------------------------------ decision --


def test_equal_timing_is_not_an_oracle() -> None:
    ok, _ = classify_timing([0.100] * 10, [0.101] * 10)
    assert ok is False


def test_blatant_gap_is_an_oracle() -> None:
    ok, detail = classify_timing([0.010] * 10, [0.100] * 10)
    assert ok is True
    assert "Δ" in detail


def test_noisy_but_overlapping_is_not_an_oracle() -> None:
    # Big within-class spread, small between-class gap → noise dominates, no flag.
    early = [0.10, 0.14, 0.08, 0.13, 0.09]
    late = [0.11, 0.09, 0.15, 0.08, 0.12]
    ok, _ = classify_timing(early, late)
    assert ok is False


def test_small_gap_below_absolute_floor_is_not_an_oracle() -> None:
    # A crisp but tiny 5ms separation is below the 25ms floor — not actionable.
    ok, _ = classify_timing([0.100] * 10, [0.105] * 10)
    assert ok is False


# ------------------------------------------------------------------- evaluate --


def test_evaluate_timing_none_skips_and_carries_the_id() -> None:
    results = evaluate_timing(None)
    assert len(results) == 1
    assert results[0].check_id == TIMING_CHECK_ID
    assert results[0].status is Status.SKIP


def _scripted_clock(durations: list[float]) -> Callable[[], float]:
    """A fake perf_counter: yields (start, start+d) for each per-send duration."""
    vals: list[float] = []
    t = 0.0
    for d in durations:
        vals.append(t)
        vals.append(t + d)
        t += d + 1.0
    it = iter(vals)
    return lambda: next(it)


def _ctx():
    pytest.importorskip("eth_account")
    import httpx
    from conftest import VALID_PAYMENT_REQUIRED, encode_header

    from x402_conformance.active import build_active_context
    from x402_conformance.payload_builder import EvmSigner

    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("PAYMENT-SIGNATURE") is None:
            return httpx.Response(
                402, headers={"PAYMENT-REQUIRED": encode_header(VALID_PAYMENT_REQUIRED)}
            )
        return httpx.Response(402)  # every tampered payment is rejected

    client = httpx.Client(transport=httpx.MockTransport(handler))
    return build_active_context(
        client, "https://t.example", "GET", EvmSigner.from_key("0x" + "55" * 32)
    )


def test_evaluate_timing_flags_a_scripted_oracle() -> None:
    ctx = _ctx()
    # class-A (wrong signature) samples fast, class-B (wrong amount) slow → oracle.
    clock = _scripted_clock([0.010] * 15 + [0.100] * 15)
    result = evaluate_timing(ctx, samples=15, time_fn=clock)[0]
    assert result.check_id == TIMING_CHECK_ID
    assert result.status is Status.FAIL
    assert "timing oracle" in result.detail


def test_evaluate_timing_passes_a_constant_time_endpoint() -> None:
    ctx = _ctx()
    clock = _scripted_clock([0.050] * 15 + [0.050] * 15)  # both classes equal
    result = evaluate_timing(ctx, samples=15, time_fn=clock)[0]
    assert result.status is Status.PASS
