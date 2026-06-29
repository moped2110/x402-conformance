"""Drift guard for the facilitator error-reason registry.

`KNOWN_ERROR_CODES` gates FA-ERR (an `invalidReason`/`errorReason` outside it is a
FAIL). Its canonical half, `SPEC_ERROR_REASONS`, is vendored from the x402 spec's
`ErrorReasons` enum and must stay in sync — otherwise the suite false-flags a
legitimate spec code, or accepts one the spec dropped.

Two layers:
  * a CI-safe pin, so the vendored set can't be edited by accident; and
  * a live diff against a real `x402Specs.ts` when one is reachable (set
    `X402_SPEC_TS`, or have the x402 clone checked out next to this repo). It
    skips when the file isn't present, so upstream CI stays green.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from x402_conformance.checks.facilitator import (
    KNOWN_ERROR_CODES,
    SPEC_ERROR_REASONS,
    _LOCAL_ERROR_CODES,
)

# Relative locations of x402Specs.ts to try when X402_SPEC_TS isn't set. Best
# effort — the env var is the reliable path; these cover the clone sitting beside
# this repo (…/Projects/x402 next to …/Projects/cryptodominance/01-x402-testsuite).
_SPEC_REL = "typescript/packages/legacy/x402/src/types/verify/x402Specs.ts"
_CANDIDATES = (
    f"../../../x402/{_SPEC_REL}",
    f"../../../../x402/{_SPEC_REL}",
    f"../../x402/{_SPEC_REL}",
)


def _find_spec_file() -> Path | None:
    env = os.environ.get("X402_SPEC_TS")
    if env:
        p = Path(env)
        return p if p.is_file() else None
    here = Path(__file__).resolve().parent
    for rel in _CANDIDATES:
        p = (here / rel).resolve()
        if p.is_file():
            return p
    return None


def _parse_error_reasons(text: str) -> set[str]:
    block = re.search(r"ErrorReasons\s*=\s*\[(.*?)\]\s*as\s+const", text, re.S)
    assert block, "could not locate the `ErrorReasons` array in x402Specs.ts"
    return set(re.findall(r'"([^"]+)"', block.group(1)))


def test_spec_error_reasons_pinned():
    """CI-safe: the vendored set is exactly what we reviewed (40 unique codes),
    and the local extensions stay out of the canonical half."""
    assert len(SPEC_ERROR_REASONS) == 40
    # canonical settle/verify reasons live in the spec half, short form
    assert {"unexpected_settle_error", "unexpected_verify_error"} <= SPEC_ERROR_REASONS
    # the current spec spelling, not the legacy *_value_mismatch
    assert "invalid_exact_evm_payload_authorization_value" in SPEC_ERROR_REASONS
    assert "invalid_exact_evm_payload_authorization_value_mismatch" not in SPEC_ERROR_REASONS
    # local-only codes are not smuggled into the canonical set
    assert SPEC_ERROR_REASONS.isdisjoint(_LOCAL_ERROR_CODES)
    assert _LOCAL_ERROR_CODES <= KNOWN_ERROR_CODES


def test_known_error_codes_match_spec_enum():
    """Live drift guard: SPEC_ERROR_REASONS must equal the `ErrorReasons` enum in
    an actual x402Specs.ts. Skips when the spec source isn't reachable."""
    path = _find_spec_file()
    if path is None:
        pytest.skip(
            "x402Specs.ts not found; set X402_SPEC_TS or check out the x402 clone "
            "beside this repo to enable the live drift guard"
        )
    live = _parse_error_reasons(path.read_text(encoding="utf-8"))
    missing = live - SPEC_ERROR_REASONS  # spec added codes we don't vendor yet
    extra = SPEC_ERROR_REASONS - live  # codes we vendor that the spec dropped
    assert not missing and not extra, (
        f"SPEC_ERROR_REASONS drifted from {path.name}: "
        f"missing from ours {sorted(missing)}; not in spec {sorted(extra)}"
    )
