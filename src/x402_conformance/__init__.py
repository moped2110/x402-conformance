"""x402-conformance: black-box conformance testing for x402 payment endpoints."""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

try:
    #: Single source of truth: the installed distribution version (from pyproject).
    __version__ = _pkg_version("x402-conformance")
except PackageNotFoundError:  # running from a source tree without an installed dist
    __version__ = "0.0.0+source"

#: Spec snapshot all checks are written against. Update deliberately, never silently.
SPEC_BASELINE = "x402 Protocol v2 — x402-foundation/x402 @ d454eb9 (2026-06-08)"

#: Sent on every outbound request so a scanned endpoint's logs can identify the tool
#: (and its real repo). One constant, one version — never hand-typed per call site.
USER_AGENT = f"x402-conformance/{__version__} (+https://github.com/moped2110/x402-conformance)"
