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


#: Machine-readable reason attached to a SKIP that we chose *not* to judge, as opposed
#: to one that was simply not applicable. A run containing one can never be CONFORMANT
#: (see ``report.assessment_exit_code``): certifying conformance while stating that a
#: gating point was not judged would contradict itself.
#:
#: Today the only instance is the Algorand CAIP-2 identifier form, reported upstream as
#: x402-foundation/x402#2904. This is the first reason code; when more appear they
#: belong in an enum alongside it rather than as free text.
DEFERRED_PENDING_UPSTREAM = "deferred_pending_upstream"

CheckFunc = Callable[["ProbeSession"], tuple[Status, str]]


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
