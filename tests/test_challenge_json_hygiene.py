"""RS-PR-021/022: the challenge has to be JSON every client can read the same way.

Python's decoder is unusually permissive. It accepts `NaN` and `Infinity`, which
RFC 8259 does not define, and it silently collapses duplicate keys to last-wins.
Go's encoding/json rejects the first and behaves differently on the second. So a
challenge can look perfectly fine to a Python client and be unreadable — or mean
something else — to somebody else's.

That is a conformance finding about the endpoint, not merely hostile input to
defend against, which is why these are checks with verdicts rather than a parser
that refuses. The parse itself is deliberately unchanged: every other check reads
the same document it always did.
"""

from __future__ import annotations

import base64
import json

from conftest import TARGET_URL, transport_with_402
from test_handshake import by_id

from x402_conformance.checks import Status
from x402_conformance.report import exit_code
from x402_conformance.runner import run_checks


def raw_header(text: str) -> str:
    """Base64 one hand-written challenge, bypassing json.dumps."""
    return base64.b64encode(text.encode()).decode()


def run_raw(text: str) -> list:
    """Run the passive checks against a hand-written challenge."""
    return run_checks(TARGET_URL, transport=transport_with_402(header_value=raw_header(text)))


# --- RS-PR-021: no literals RFC 8259 does not define --------------------------


def test_a_clean_challenge_passes(valid_payload: dict) -> None:
    """The spec example uses only standard JSON."""
    results = run_checks(TARGET_URL, transport=transport_with_402(valid_payload))
    assert by_id(results, "RS-PR-021").status == Status.PASS


def test_nan_in_the_challenge_is_a_failure(valid_payload: dict) -> None:
    """json.dumps emits a bare NaN; RFC 8259 has no such literal."""
    valid_payload["accepts"][0]["maxTimeoutSeconds"] = float("nan")
    results = run_checks(TARGET_URL, transport=transport_with_402(valid_payload))
    result = by_id(results, "RS-PR-021")

    assert result.status == Status.FAIL
    assert "NaN" in result.detail
    assert exit_code(results) == 1  # MAJOR gates


def test_infinity_is_caught_too(valid_payload: dict) -> None:
    """The other two non-standard literals are named individually."""
    valid_payload["accepts"][0]["maxTimeoutSeconds"] = float("inf")
    results = run_checks(TARGET_URL, transport=transport_with_402(valid_payload))
    assert "Infinity" in by_id(results, "RS-PR-021").detail


# --- RS-PR-022: no duplicate object keys --------------------------------------


def test_a_challenge_without_repeats_passes(valid_payload: dict) -> None:
    """Nothing to report when every key appears once."""
    results = run_checks(TARGET_URL, transport=transport_with_402(valid_payload))
    assert by_id(results, "RS-PR-022").status == Status.PASS


def test_a_repeated_key_is_a_failure(valid_payload: dict) -> None:
    """A repeated key means different things to different parsers."""
    text = json.dumps(valid_payload)
    # Inject a second x402Version by hand: json.dumps cannot produce one.
    doubled = text.replace('{"x402Version": 2', '{"x402Version": 2, "x402Version": 99', 1)
    results = run_raw(doubled)
    result = by_id(results, "RS-PR-022")

    assert result.status == Status.FAIL
    assert "x402Version" in result.detail
    assert exit_code(results) == 1


def test_the_parse_still_behaves_exactly_as_json_does(valid_payload: dict) -> None:
    """Recording a duplicate must not change what the other checks see.

    The hook collapses last-wins, which is what json.loads does without it. If this
    drifted, every check downstream would be reading a different document than it
    used to — a silent change of meaning dressed up as a new feature.
    """
    text = json.dumps(valid_payload)
    doubled = text.replace('{"x402Version": 2', '{"x402Version": 2, "x402Version": 99', 1)
    results = run_raw(doubled)

    # Last-wins: 99 is what the document says, so the version check sees 99.
    assert by_id(results, "RS-PR-001").status == Status.FAIL
    assert "99" in by_id(results, "RS-PR-001").detail


# --- Hostile shape: refused, not crashed, and not graded ----------------------


def test_deep_nesting_does_not_crash_the_run() -> None:
    """A header of a thousand open brackets fits in under a kilobyte.

    Python's decoder exhausts its stack on it and raises RecursionError, which is
    not a JSONDecodeError and would have escaped the run. SECURITY.md puts crashes
    on hostile input in scope.
    """
    results = run_raw("[" * 4000 + "]" * 4000)

    # No verdict is claimed about an endpoint whose challenge could not be read.
    assert by_id(results, "RS-PR-021").status == Status.SKIP
    assert by_id(results, "RS-PR-022").status == Status.SKIP


def test_an_oversized_challenge_is_refused_rather_than_parsed() -> None:
    """Bounded before the decoder sees it, so size cannot become work."""
    results = run_raw('{"padding": "' + "x" * (300 * 1024) + '"}')
    assert by_id(results, "RS-PR-021").status == Status.SKIP
