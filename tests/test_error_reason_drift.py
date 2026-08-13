"""Drift guard for the facilitator error-reason registry.

`KNOWN_ERROR_CODES` gates FA-ERR (an `invalidReason`/`errorReason` outside it is a
FAIL), so a code missing from it makes us fail a facilitator that is behaving
correctly. It has two vendored halves, and each needs its own guard:

  * `SPEC_ERROR_REASONS` — the legacy `ErrorReasons` Zod enum. Frozen upstream at
    41 codes under `legacy/`; still enforced, no longer extended.
  * `MECHANISM_ERROR_CODES` — `src/x402_conformance/error_registry.py`, generated
    by `tools/sync_error_registry.py` from the per-mechanism declarations that
    upstream adds codes to now.

Layers, mirroring the structure the suite already uses for the enum:
  * CI-safe pins, so neither vendored set can be edited by accident; and
  * live diffs against a real upstream clone when one is reachable (set
    `X402_SPEC_TS` to an `x402Specs.ts`, or `X402_UPSTREAM` to a clone root, or
    have the clone checked out next to this repo). They skip when the source
    isn't present, so CI without a clone stays green.

The second half exists because of a real miss: upstream's package split moved new
codes out of the enum, and a guard that watched only the enum stayed green while
the accepted vocabulary fell ~300 codes behind what conformant facilitators
return.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import pytest

from x402_conformance.checks.facilitator import (
    _LOCAL_ERROR_CODES,
    KNOWN_ERROR_CODES,
    SPEC_ERROR_REASONS,
)
from x402_conformance.error_registry import MECHANISM_ERROR_CODES

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from sync_error_registry import extract, render  # noqa: E402

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
    # A clone root enables both guards, so accept it here too rather than making
    # the caller set two variables that point into the same tree.
    root = os.environ.get("X402_UPSTREAM")
    if root:
        p = Path(root) / _SPEC_REL
        return p if p.is_file() else None
    here = Path(__file__).resolve().parent
    for rel in _CANDIDATES:
        p = (here / rel).resolve()
        if p.is_file():
            return p
    return None


def _find_upstream_root() -> Path | None:
    """Locate an x402 clone root for the mechanism-registry diff.

    Prefers `X402_UPSTREAM`, then derives the root from `X402_SPEC_TS` (the var
    the enum guard already uses), then the sibling-clone candidates.
    """
    env = os.environ.get("X402_UPSTREAM")
    if env:
        p = Path(env)
        return p if (p / "specs").is_dir() else None
    spec = _find_spec_file()
    if spec is not None:
        # …/<root>/typescript/packages/legacy/x402/src/types/verify/x402Specs.ts
        root = spec.parents[7]
        if (root / "specs").is_dir():
            return root
    return None


def _reviewed_pin() -> str | None:
    """Read the upstream commit this repository claims to have reviewed."""
    pin = Path(__file__).resolve().parents[1] / ".github" / "upstream-reviewed-commit"
    if not pin.is_file():
        return None
    text = pin.read_text(encoding="utf-8").strip()
    return text or None


def _clone_head(root: Path) -> str | None:
    """Resolve a clone's checked-out commit without shelling out to git."""
    head = root / ".git" / "HEAD"
    if not head.is_file():
        return None
    text = head.read_text(encoding="utf-8").strip()
    if not text.startswith("ref:"):
        return text or None
    ref = text.split(":", 1)[1].strip()
    loose = root / ".git" / ref
    if loose.is_file():
        return loose.read_text(encoding="utf-8").strip() or None
    packed = root / ".git" / "packed-refs"
    if packed.is_file():
        for line in packed.read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1] == ref:
                return parts[0]
    return None


def _clone_is_at_reviewed_pin(root: Path) -> str | None:
    """Return a skip reason when the clone is not the tree we reviewed.

    The live diffs only mean "we drifted" when they compare against the pin this
    repository reviewed. Against any other tree they still go red, but the remedy
    differs and the failure text cannot tell the cases apart:

      * an **older** clone lacks codes we correctly vendored — the fix is
        `git fetch`, not regenerating anything;
      * a **newer** clone has codes we have not reviewed yet — the fix is an
        upstream review window, and regenerating would vendor unreviewed codes
        while making the guard green, which is worse than the red we started with.

    Both previously said "rerun sync_error_registry", which is wrong in both. A
    gate that goes red without a defect gets ignored after the third time, so this
    skips with the reason instead.
    """
    pin = _reviewed_pin()
    if pin is None:
        return None
    head = _clone_head(root)
    if head is None:
        return f"cannot read the clone's HEAD at {root}; expected the reviewed pin {pin}"
    if not head.startswith(pin) and not pin.startswith(head):
        return (
            f"clone at {root} is checked out at {head[:12]}, not the reviewed pin {pin}. "
            "Check out the pin to compare, or open an upstream review window if the "
            "clone is ahead — do not regenerate against an unreviewed tree."
        )
    return None


def _parse_error_reasons(text: str) -> set[str]:
    block = re.search(r"ErrorReasons\s*=\s*\[(.*?)\]\s*as\s+const", text, re.S)
    assert block, "could not locate the `ErrorReasons` array in x402Specs.ts"
    return set(re.findall(r'"([^"]+)"', block.group(1)))


def test_spec_error_reasons_pinned():
    """CI-safe: the vendored enum is exactly what we reviewed (41 unique codes),
    and the local extensions stay out of the canonical half."""
    assert len(SPEC_ERROR_REASONS) == 41
    # canonical settle/verify reasons live in the spec half, short form
    assert {"unexpected_settle_error", "unexpected_verify_error"} <= SPEC_ERROR_REASONS
    # both the short spelling and *_value_mismatch are now first-class spec codes
    # (upstream adopted _value_mismatch into the TS enum — our former T-20 nit)
    assert "invalid_exact_evm_payload_authorization_value" in SPEC_ERROR_REASONS
    assert "invalid_exact_evm_payload_authorization_value_mismatch" in SPEC_ERROR_REASONS
    # local-only codes are not smuggled into the canonical set
    assert SPEC_ERROR_REASONS.isdisjoint(_LOCAL_ERROR_CODES)
    assert _LOCAL_ERROR_CODES <= KNOWN_ERROR_CODES


def test_mechanism_error_codes_pinned():
    """CI-safe: the generated mechanism registry is the set we reviewed."""
    assert len(MECHANISM_ERROR_CODES) == 344
    # The two codes upstream added since the last reviewed pin, and the reason
    # this half exists at all: neither is in the legacy enum.
    assert "invalid_exact_evm_transfer_event_mismatch" in MECHANISM_ERROR_CODES
    assert "extension_echo_mismatch" in MECHANISM_ERROR_CODES
    assert {"invalid_exact_evm_transfer_event_mismatch", "extension_echo_mismatch"}.isdisjoint(
        SPEC_ERROR_REASONS
    )
    # The spelling that motivated the union: the current EVM package's
    # `..._authorization_value` differs from the enum's `..._payload_authorization_value`.
    assert "invalid_exact_evm_authorization_value" in MECHANISM_ERROR_CODES
    assert "invalid_exact_evm_authorization_value" not in SPEC_ERROR_REASONS


def test_known_error_codes_is_the_union():
    """FA-ERR-001 must accept both halves, not just the frozen enum."""
    assert SPEC_ERROR_REASONS <= KNOWN_ERROR_CODES
    assert MECHANISM_ERROR_CODES <= KNOWN_ERROR_CODES
    assert KNOWN_ERROR_CODES == SPEC_ERROR_REASONS | MECHANISM_ERROR_CODES | _LOCAL_ERROR_CODES


def test_known_error_codes_match_spec_enum():
    """Live drift guard: SPEC_ERROR_REASONS must equal the `ErrorReasons` enum in
    an actual x402Specs.ts. Skips when the spec source isn't reachable."""
    path = _find_spec_file()
    if path is None:
        pytest.skip(
            "x402Specs.ts not found; set X402_SPEC_TS or check out the x402 clone "
            "beside this repo to enable the live drift guard"
        )
    root = _find_upstream_root()
    if root is not None and (reason := _clone_is_at_reviewed_pin(root)) is not None:
        pytest.skip(reason)
    live = _parse_error_reasons(path.read_text(encoding="utf-8"))
    missing = live - SPEC_ERROR_REASONS  # spec added codes we don't vendor yet
    extra = SPEC_ERROR_REASONS - live  # codes we vendor that the spec dropped
    assert not missing and not extra, (
        f"SPEC_ERROR_REASONS drifted from {path.name}: "
        f"missing from ours {sorted(missing)}; not in spec {sorted(extra)}"
    )


def test_mechanism_registry_matches_upstream():
    """Live drift guard for the generated half: re-extract from a real clone and
    compare byte-for-byte with the committed module.

    This is the guard the enum-only version lacked. Skips without a clone.
    """
    root = _find_upstream_root()
    if root is None:
        pytest.skip(
            "no x402 clone found; set X402_UPSTREAM (or X402_SPEC_TS) to enable "
            "the mechanism-registry drift guard"
        )
    if (reason := _clone_is_at_reviewed_pin(root)) is not None:
        pytest.skip(reason)
    generated = render(extract(root))
    committed = (
        Path(__file__).resolve().parents[1] / "src" / "x402_conformance" / "error_registry.py"
    ).read_text(encoding="utf-8")
    if generated == committed:
        return
    live_codes = set().union(*extract(root).values())
    missing = sorted(live_codes - MECHANISM_ERROR_CODES)
    extra = sorted(MECHANISM_ERROR_CODES - live_codes)
    pytest.fail(
        "error_registry.py drifted from upstream — rerun "
        f"`python tools/sync_error_registry.py --upstream {root}`. "
        f"Upstream declares but we reject: {missing}; we accept but upstream dropped: {extra}"
    )
