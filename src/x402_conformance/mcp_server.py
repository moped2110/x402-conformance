"""An MCP server exposing the passive conformance surface to coding agents.

The point is to remove a step. Someone building an x402 endpoint in an editor
should be able to ask "is this conformant?" and get the same answer the CLI
gives, without leaving the editor, copying a URL into a terminal, or reading a
JSON file back. The checks, the catalog and the diff are the same code paths the
CLI drives — this module adds a protocol, not a second implementation.

What this server deliberately cannot do
---------------------------------------

It cannot sign a payment, settle one, or probe a facilitator's ``/verify``. Not
"it refuses to by default" — the tools do not take a signer key, an RPC URL or an
``active`` flag, and this module never imports the signing path. That is a
structural choice, not a policy one, and it follows from what an MCP server is:
a surface an autonomous agent drives without a human reading each call. SECURITY.md
states that transactional modes "cannot be enabled by an auto-discovered TOML
config; they require an explicit flag per run". An agent deciding for itself to
sign something is precisely the case that rule exists to prevent, so the flag has
no representation here at all.

The passive checks are still real network calls to a third-party endpoint: two
unpaid HTTP requests, exactly what a client that cannot pay would send. That is
the most an agent should be able to initiate on its own recognisance.

How far those calls may reach depends on the transport, because the transport
decides who is calling. On stdio the caller is the person who started the server
and has exactly their reach, so a local address is theirs to fetch — which is the
main use case, testing the endpoint you are building on localhost. Over ``sse`` or
``streamable-http`` the server is reachable by others, and a target that resolves
inside the network would make it an SSRF pivot whose response comes back inside
the check details. On those transports only public destinations are fetched. The
policy is the Bazaar cross-fetch policy, imported rather than restated.

Anything transactional stays where a human types it: the CLI, one flag, one run.
"""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib.parse import urlsplit

import httpx

from . import __version__
from .diff import diff_reports as _diff_reports
from .report import (
    assessment_exit_code,
    assessment_reason,
    summarize,
    to_json,
)
from .report import (
    explain_check as _explain_check,
)
from .runner import EndpointUnreachable, run_checks

# The transports this server understands. stdio is what an editor spawns; the
# HTTP ones exist for a shared deployment and are chosen by the operator, never
# by a caller.
TRANSPORTS = ("stdio", "sse", "streamable-http")

# The transports that expose this server to somebody other than the person who
# started it. On stdio the caller already has exactly the user's own reach, so a
# local address is theirs to fetch and blocking it would break the main use case:
# testing the endpoint you are building on localhost. Over HTTP the server becomes
# a request primitive aimed at whatever host appears in a prompt, and a target that
# resolves inside the network is an SSRF pivot whose response comes back in the
# check details.
SHARED_TRANSPORTS = frozenset({"sse", "streamable-http"})

log = logging.getLogger("x402_conformance.mcp")


def _non_public_refusal(url: str) -> str | None:
    """Return why a URL may not be fetched over a shared transport, or None.

    Delegates to the Bazaar cross-fetch policy instead of restating it. Two address
    policies in one package would drift apart, and that one already handles IP
    literals, IDNA hostnames and the special-use ranges Python still calls global.
    """
    from .checks.discovery import (
        CrossFetchError,
        _canonical_host,
        _is_public_address,
        _resolve_addresses,
        _system_resolver,
    )

    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"}:
        return f"unsupported URL scheme {parsed.scheme!r}: only http and https are fetched"
    if not parsed.hostname:
        return "the URL has no host"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        host = _canonical_host(parsed.hostname)
        addresses = _resolve_addresses(host, port, _system_resolver)
    except (ValueError, CrossFetchError) as exc:
        return str(exc)
    if all(_is_public_address(address) for address in addresses):
        return None
    return (
        f"{host} resolves to a non-public address. This server is reachable over a "
        "shared transport, so it will not fetch destinations the caller could not "
        "reach itself. Run it on stdio to test an endpoint on your own machine."
    )


INSTRUCTIONS = """\
Conformance testing for x402 payment endpoints, against the pinned spec baseline.

Use check_endpoint to test a live endpoint: it sends two unpaid requests and
evaluates the handshake and PaymentRequired-schema checks. Use explain_check to
find out what a failing check ID means and how to fix it — that is offline and
free, so prefer it over guessing at a check's intent. Use diff_reports after a
fix to confirm the fix landed and nothing else regressed.

This server performs no payments and cannot sign or settle one. Checks that
require signing a payment, or probing a facilitator's /verify or /settle, are
available only through the command-line tool, where a person enables them
explicitly per run.\
"""


def _failure_digest(results: list[Any]) -> list[dict[str, str]]:
    """Reduce a result list to the failures, in the shape an agent has to act on.

    Passing checks are the overwhelming majority and carry no instruction; sending
    all of them costs context the caller could spend on the ones that need work.
    The full report stays available in the same response.
    """
    return [
        {
            "check_id": result.check_id,
            "title": result.title,
            "severity": str(result.severity),
            "detail": result.detail,
            "spec_ref": result.spec_ref,
        }
        for result in results
        if str(result.status).lower().endswith("fail")
    ]


def build_server(transport: str = "stdio") -> Any:
    """Construct the MCP server with the passive conformance tools bound.

    Imported lazily by ``main`` so that the optional MCP dependency is only
    required by somebody actually starting the server, not by importing the
    package.

    ``transport`` decides how far a caller may reach: see ``SHARED_TRANSPORTS``.
    It is the operator's choice at start-up, never a tool argument, because the
    whole point is that the caller cannot widen it.
    """
    from mcp.server.mcpserver import MCPServer

    guard_targets = transport in SHARED_TRANSPORTS

    server = MCPServer(
        name="x402-conformance",
        title="x402 conformance",
        version=__version__,
        instructions=INSTRUCTIONS,
    )

    @server.tool(
        description=(
            "Test whether a live x402 endpoint conforms to the spec. Sends two "
            "unpaid HTTP requests and evaluates the handshake and "
            "PaymentRequired-schema checks. Performs no payment and signs "
            "nothing. Returns a verdict, per-severity counts, and every failing "
            "check with its detail and spec reference."
        )
    )
    def check_endpoint(url: str, method: str = "GET", timeout: float = 10.0) -> dict[str, Any]:
        """Run the passive conformance checks against one endpoint."""
        if guard_targets and (refusal := _non_public_refusal(url)) is not None:
            return {
                "verdict": "refused",
                "reason": refusal,
                "target": url,
                "summary": None,
                "failures": [],
            }
        try:
            results = run_checks(url, method=method, timeout=timeout)
        except EndpointUnreachable as exc:
            # Not a conformance failure: the endpoint never answered in a way that
            # could be judged. Saying "not conformant" here would be a false verdict.
            return {
                "verdict": "inconclusive",
                "reason": str(exc),
                "target": url,
                "summary": None,
                "failures": [],
            }
        except httpx.HTTPError as exc:
            # The exception text carries transport internals and, on a shared
            # deployment, describes hosts the caller may not be entitled to learn
            # about. It goes to the operator's log; the caller gets the verdict.
            log.warning("check_endpoint transport failure for %r: %s", url, exc)
            return {
                "verdict": "inconclusive",
                "reason": "the request failed before the endpoint could be judged",
                "target": url,
                "summary": None,
                "failures": [],
            }

        code = assessment_exit_code(results)
        return {
            "verdict": {0: "conformant", 1: "not_conformant", 2: "inconclusive"}.get(
                code, "unknown"
            ),
            "reason": assessment_reason(results),
            "target": url,
            "summary": summarize(results),
            "failures": _failure_digest(results),
            # The full versioned report, so the caller can hand it straight to
            # diff_reports after a fix without running the check twice.
            "report": json.loads(to_json(results, url, code)),
        }

    @server.tool(
        description=(
            "Explain what a conformance check tests, why it matters, its severity "
            "and how to fix a failure. Offline: no endpoint is contacted. Pass a "
            "check ID (RS-NEG-007), a prefix (RS-SEC) to list a group, or nothing "
            "to list the whole catalog."
        )
    )
    def explain_check(query: str | None = None) -> str:
        """Return the plain-language explanation for a check ID, prefix or the catalog."""
        return _explain_check(query)

    @server.tool(
        description=(
            "Compare two conformance reports from check_endpoint to see whether a "
            "fix worked. Classifies each check as fixed, regressed, still-failing, "
            "added or removed. Offline."
        )
    )
    def diff_reports(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
        """Classify the transitions between two versioned conformance reports."""
        try:
            result = _diff_reports(json.dumps(before), json.dumps(after))
        except ValueError as exc:
            return {"error": f"cannot diff: {exc}"}
        return {
            "has_regressions": result.has_regressions,
            "fixed": [t.check_id for t in result.fixed],
            "regressed": [t.check_id for t in result.regressed],
            "still_failing": [t.check_id for t in result.still_failing],
            # Already check IDs, unlike the transition lists above: a check that
            # only exists on one side has no before-and-after to carry.
            "added": list(result.added),
            "removed": list(result.removed),
        }

    @server.tool(
        description=(
            "Run the discovery/Bazaar checks (DI-*) against a facilitator or "
            "directory base URL that exposes /discovery/resources. Read-only."
        )
    )
    def check_discovery(url: str, timeout: float = 10.0) -> dict[str, Any]:
        """Run the discovery conformance checks against one Bazaar base URL."""
        from .checks.discovery import run_discovery_checks

        if guard_targets and (refusal := _non_public_refusal(url)) is not None:
            return {
                "verdict": "refused",
                "reason": refusal,
                "target": url,
                "summary": None,
                "failures": [],
            }
        try:
            results = run_discovery_checks(url, timeout=timeout)
        except httpx.HTTPError as exc:
            log.warning("check_discovery transport failure for %r: %s", url, exc)
            return {
                "verdict": "inconclusive",
                "reason": "the discovery endpoint could not be reached",
                "target": url,
                "summary": None,
                "failures": [],
            }
        code = assessment_exit_code(results)
        return {
            "verdict": {0: "conformant", 1: "not_conformant", 2: "inconclusive"}.get(
                code, "unknown"
            ),
            "target": url,
            "summary": summarize(results),
            "failures": _failure_digest(results),
        }

    return server


def main() -> None:
    """Start the MCP server on the transport named by ``X402_MCP_TRANSPORT``."""
    import os
    import sys

    transport = os.environ.get("X402_MCP_TRANSPORT", "stdio")
    if transport not in TRANSPORTS:
        # stderr, not stdout: on stdio the protocol owns stdout, and a stray line
        # there corrupts the stream rather than reaching a human.
        print(
            f"unsupported X402_MCP_TRANSPORT {transport!r}; expected one of {TRANSPORTS}",
            file=sys.stderr,
        )
        raise SystemExit(2)
    build_server(transport).run(transport=transport)


if __name__ == "__main__":
    main()
