"""Check registry with spec traceability.

Every check is registered with an ID, severity, and a reference to the exact
spec location it verifies (catalog: docs/conformance-catalog.md). Checks never
raise on bad endpoint behavior — they return FAIL/SKIP with a detail message.
"""

from __future__ import annotations

import enum
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..probe import ProbeSession


class Severity(str, enum.Enum):
    CRITICAL = "critical"  # security / funds at risk
    MAJOR = "major"        # spec violation, interop broken
    MINOR = "minor"        # robustness / quality


class Status(str, enum.Enum):
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"   # precondition not met (e.g. no 402 to inspect)
    ERROR = "error"  # the check itself crashed — a bug in this suite


CheckFunc = Callable[["ProbeSession"], tuple[Status, str]]


@dataclass(frozen=True)
class Check:
    check_id: str
    title: str
    severity: Severity
    spec_ref: str
    func: CheckFunc


@dataclass(frozen=True)
class CheckResult:
    check_id: str
    title: str
    severity: Severity
    spec_ref: str
    status: Status
    detail: str = ""


REGISTRY: list[Check] = []


def register(
    check_id: str, title: str, severity: Severity, spec_ref: str
) -> Callable[[CheckFunc], CheckFunc]:
    """Decorator: add a check function to the global registry."""

    def decorator(func: CheckFunc) -> CheckFunc:
        if any(c.check_id == check_id for c in REGISTRY):
            raise ValueError(f"duplicate check id: {check_id}")
        REGISTRY.append(Check(check_id, title, severity, spec_ref, func))
        return func

    return decorator
