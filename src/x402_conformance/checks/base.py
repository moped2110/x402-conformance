"""Check registry with spec traceability.

Every check is registered with an ID, severity, and a reference to the exact
spec location it verifies (catalog: docs/conformance-catalog.md). Checks never
raise on bad endpoint behavior — they return FAIL/SKIP with a detail message.
"""

from __future__ import annotations

import enum
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from ..probe import ProbeSession


class Severity(str, enum.Enum):
    """How bad a failure is. Drives the CI gate: a failed CRITICAL/MAJOR check
    sets a non-zero exit code; MINOR is advisory."""

    CRITICAL = "critical"  # security / funds at risk
    MAJOR = "major"  # spec violation, interop broken
    MINOR = "minor"  # robustness / quality


class Status(str, enum.Enum):
    """Outcome of running one check against a target."""

    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"  # precondition not met (e.g. no 402 to inspect)
    ERROR = "error"  # the check itself crashed — a bug in this suite


# --- Machine-readable reason codes -----------------------------------------------
#
# Two related vocabularies. A **per-check** ``reason_code`` qualifies one SKIP; a
# **run-level** inconclusive reason qualifies the whole exit-2 verdict (report's
# top-level ``inconclusiveReason``). The run-level set is a superset: it reuses the
# two per-check codes and adds the reasons only the runner/CLI can know.

#: Per-check: a SKIP we chose *not* to judge (as opposed to one simply not applicable).
#: A run containing one can never be CONFORMANT (see ``report.assessment_exit_code``):
#: certifying conformance while stating a gating point was not judged is a contradiction.
#: First instance: the Algorand CAIP-2 identifier form, upstream x402-foundation/x402#2904.
DEFERRED_PENDING_UPSTREAM = "deferred_pending_upstream"

#: Per-check: the endpoint under test does not exist / is the wrong kind of endpoint —
#: e.g. a facilitator path answered by the passive resource ``check``, or a facilitator
#: sub-endpoint that returns 404/405/501. The point was not tested because there was
#: nothing of that kind there, not because it passed.
ENDPOINT_ABSENT = "endpoint_absent"

#: Run-level inconclusive reasons that only the runner or CLI can determine.
INCONCLUSIVE_UNREACHABLE = "unreachable"
INCONCLUSIVE_INVALID_INPUT = "invalid_input"
INCONCLUSIVE_NOT_X402_V2 = "not_x402_v2"
INCONCLUSIVE_NO_CHECKS_APPLICABLE = "no_checks_applicable"

#: The complete set a report's top-level ``inconclusiveReason`` may take (exit 2 only).
INCONCLUSIVE_REASONS = frozenset(
    {
        INCONCLUSIVE_UNREACHABLE,
        INCONCLUSIVE_INVALID_INPUT,
        INCONCLUSIVE_NOT_X402_V2,
        INCONCLUSIVE_NO_CHECKS_APPLICABLE,
        ENDPOINT_ABSENT,
        DEFERRED_PENDING_UPSTREAM,
    }
)

#: The values a single ``CheckResult.reason_code`` may carry.
PER_CHECK_REASON_CODES = frozenset({DEFERRED_PENDING_UPSTREAM, ENDPOINT_ABSENT})

#: A check returns ``(status, detail)`` or, when it wants to qualify a SKIP,
#: ``(status, detail, reason_code)``. The runner normalises both to a CheckResult.
CheckReturn = tuple[Status, str] | tuple[Status, str, str | None]
CheckFunc = Callable[["ProbeSession"], CheckReturn]


@dataclass(frozen=True)
class Check:
    """A registered check: its identity (id/title/severity/spec_ref) plus the
    function that runs it. The static definition, before execution."""

    check_id: str
    title: str
    severity: Severity
    spec_ref: str
    func: CheckFunc


@dataclass(frozen=True)
class CheckResult:
    """The outcome of running a `Check`: its identity carried through, plus the
    resulting `status` and a human-readable `detail`. This is what reports render."""

    check_id: str
    title: str
    severity: Severity
    spec_ref: str
    status: Status
    detail: str = ""
    #: Optional machine-readable qualifier, e.g. ``DEFERRED_PENDING_UPSTREAM``. Additive
    #: and defaulted, so every existing construction and every report reader stays valid.
    reason_code: str | None = None


REGISTRY: list[Check] = []
_RegisteredCheck = TypeVar("_RegisteredCheck")


def append_unique_check(
    registry: list[_RegisteredCheck], item: _RegisteredCheck, check_id: str
) -> None:
    """Append one check definition, rejecting duplicate IDs at import time."""
    if any(getattr(existing, "check_id", None) == check_id for existing in registry):
        raise ValueError(f"duplicate check id: {check_id}")
    registry.append(item)


def register(
    check_id: str, title: str, severity: Severity, spec_ref: str
) -> Callable[[CheckFunc], CheckFunc]:
    """Decorator: add a check function to the global registry."""

    def decorator(func: CheckFunc) -> CheckFunc:
        """Register the decorated passive check while rejecting duplicate catalog IDs."""
        append_unique_check(REGISTRY, Check(check_id, title, severity, spec_ref, func), check_id)
        return func

    return decorator
