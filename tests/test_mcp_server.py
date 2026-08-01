"""Tests for the MCP server surface (mcp_server.build_server).

The most important test here is not that the tools work — it is that the tools
that must not exist do not exist. An MCP server is driven by an agent without a
human reading each call, so the payment-safety invariant has to be a property of
the surface rather than a default somebody can flip.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
import pytest

from x402_conformance import mcp_server
from x402_conformance.checks.base import CheckResult, Severity, Status
from x402_conformance.runner import EndpointUnreachable

pytest.importorskip("mcp", reason="the MCP server is an optional extra")


def call(name: str, arguments: dict[str, Any]) -> Any:
    """Invoke one tool on a freshly built server and return its structured result."""
    server = mcp_server.build_server()
    result = asyncio.run(server.call_tool(name, arguments))
    return getattr(result, "structured_content", None) or result


def tool_names() -> set[str]:
    """Every tool this server advertises."""
    server = mcp_server.build_server()
    return {tool.name for tool in asyncio.run(server.list_tools())}


def schema_of(name: str) -> dict[str, Any]:
    """The input schema one tool advertises."""
    server = mcp_server.build_server()
    tool = next(t for t in asyncio.run(server.list_tools()) if t.name == name)
    return dict(tool.input_schema or {})


def passing(check_id: str = "RS-HS-001") -> CheckResult:
    """One passing result, for building a report without a network."""
    return CheckResult(
        check_id=check_id,
        title="Unpaid request is answered with HTTP 402",
        severity=Severity.MAJOR,
        spec_ref="transports-v2/http.md",
        status=Status.PASS,
    )


def failing(check_id: str = "RS-PR-004") -> CheckResult:
    """One failing result, carrying the detail an agent has to act on."""
    return CheckResult(
        check_id=check_id,
        title="accepts[] entries carry a payTo address",
        severity=Severity.CRITICAL,
        spec_ref="transports-v2/http.md",
        status=Status.FAIL,
        detail="accepts[0].payTo is missing",
    )


def test_no_tool_can_sign_settle_or_probe_verify() -> None:
    """The payment-safety invariant, enforced against the surface itself.

    SECURITY.md requires transactional modes to be enabled by an explicit flag per
    run, precisely so they cannot be turned on by configuration nobody read. An
    agent choosing for itself is that case with extra steps, so the capability has
    no representation here — not a default, not a parameter.
    """
    forbidden = ("pay", "settle", "signer", "signer_key", "rpc_url", "active", "private_key")
    for name in tool_names():
        parameters = set(schema_of(name).get("properties", {}))
        assert not parameters & set(forbidden), f"{name} exposes {parameters & set(forbidden)}"


def test_the_module_never_imports_the_signing_path() -> None:
    """Structural, not behavioural: a future tool cannot reach signing by accident.

    If somebody adds an import of the active/payment modules here, this fails and
    they have to make the case for it deliberately.
    """
    source = (mcp_server.__file__ or "").replace(".pyc", ".py")
    text = open(source, encoding="utf-8").read()  # noqa: SIM115 — one read, no handle kept
    for banned in ("from .active import", "from .payload_builder import", "eth_account"):
        assert banned not in text, f"mcp_server imports the signing path: {banned}"


def test_it_offers_the_passive_tools() -> None:
    """Check, explain, diff and discovery — the surface an agent can drive safely."""
    assert tool_names() == {"check_endpoint", "explain_check", "diff_reports", "check_discovery"}


def test_an_unreachable_endpoint_is_inconclusive_not_failing(monkeypatch) -> None:
    """A server that never answered has not been judged.

    Reporting "not conformant" for it would be a false verdict, and an agent would
    act on it — filing a bug against an endpoint that was merely down.
    """

    def unreachable(*args: Any, **kwargs: Any) -> list[CheckResult]:
        """Stand in for a target that never answered."""
        raise EndpointUnreachable("502 from origin, no paywall signal")

    monkeypatch.setattr(mcp_server, "run_checks", unreachable)
    result = call("check_endpoint", {"url": "https://down.test/pay"})

    assert result["verdict"] == "inconclusive"
    assert "502" in result["reason"]
    assert result["failures"] == []


def test_a_transport_error_is_also_inconclusive(monkeypatch) -> None:
    """Same reasoning for DNS and TLS failures, which arrive as a different type."""

    def boom(*args: Any, **kwargs: Any) -> list[CheckResult]:
        """Stand in for a name that does not resolve."""
        raise httpx.ConnectError("nodename nor servname provided")

    monkeypatch.setattr(mcp_server, "run_checks", boom)
    assert call("check_endpoint", {"url": "https://nope.test/x"})["verdict"] == "inconclusive"


def test_it_returns_the_failures_with_what_is_wrong(monkeypatch) -> None:
    """A verdict alone is not actionable; the detail and the spec reference are."""
    monkeypatch.setattr(mcp_server, "run_checks", lambda *a, **k: [passing(), failing()])
    result = call("check_endpoint", {"url": "https://api.test/pay"})

    assert result["verdict"] == "not_conformant"
    assert len(result["failures"]) == 1
    failure = result["failures"][0]
    assert failure["check_id"] == "RS-PR-004"
    assert failure["detail"] == "accepts[0].payTo is missing"
    assert failure["spec_ref"]


def test_passing_checks_are_summarized_rather_than_listed(monkeypatch) -> None:
    """67 passing checks would crowd out the handful that need work.

    The counts still say what ran, and the full report is in the same response for
    anyone who needs it.
    """
    monkeypatch.setattr(
        mcp_server, "run_checks", lambda *a, **k: [passing(f"RS-HS-00{n}") for n in range(1, 6)]
    )
    result = call("check_endpoint", {"url": "https://api.test/pay"})

    assert result["verdict"] == "conformant"
    assert result["failures"] == []
    assert result["summary"]["passed"] == 5
    assert result["summary"]["total"] == 5
    assert len(result["report"]["results"]) == 5


def test_the_report_can_be_fed_straight_back_into_diff(monkeypatch) -> None:
    """The round trip is the workflow: check, fix, check, diff — without a file."""
    monkeypatch.setattr(mcp_server, "run_checks", lambda *a, **k: [failing()])
    before = call("check_endpoint", {"url": "https://api.test/pay"})["report"]

    monkeypatch.setattr(mcp_server, "run_checks", lambda *a, **k: [passing("RS-PR-004")])
    after = call("check_endpoint", {"url": "https://api.test/pay"})["report"]

    diff = call("diff_reports", {"before": before, "after": after})
    assert diff["fixed"] == ["RS-PR-004"]
    assert diff["regressed"] == []
    assert diff["has_regressions"] is False


def test_a_regression_is_reported_as_one(monkeypatch) -> None:
    """The reason an agent runs the diff at all: did my change break something else."""
    monkeypatch.setattr(mcp_server, "run_checks", lambda *a, **k: [passing("RS-PR-004")])
    before = call("check_endpoint", {"url": "https://api.test/pay"})["report"]
    monkeypatch.setattr(mcp_server, "run_checks", lambda *a, **k: [failing()])
    after = call("check_endpoint", {"url": "https://api.test/pay"})["report"]

    diff = call("diff_reports", {"before": before, "after": after})
    assert diff["regressed"] == ["RS-PR-004"]
    assert diff["has_regressions"] is True


def test_diffing_something_that_is_not_a_report_says_so() -> None:
    """An agent that hands over the wrong object needs a message, not a stack trace."""
    result = call("diff_reports", {"before": {"nonsense": True}, "after": {"nonsense": True}})
    assert "error" in result


def test_explain_works_offline_for_an_id_a_prefix_and_the_catalog() -> None:
    """Explaining a check costs nothing, so an agent should reach for it first."""
    single = call("explain_check", {"query": "RS-HS-001"})
    group = call("explain_check", {"query": "RS-SEC"})
    everything = call("explain_check", {})

    text = json.dumps([single, group, everything])
    assert "RS-HS-001" in text
    assert len(json.dumps(everything)) > len(json.dumps(single))


def test_the_instructions_state_the_boundary() -> None:
    """The client shows these to the model; the limit belongs where it will be read."""
    assert "no payments" in mcp_server.INSTRUCTIONS
    assert "command-line tool" in mcp_server.INSTRUCTIONS
