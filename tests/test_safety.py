"""Release-blocking payment-network and redirect safety regression tests."""

from __future__ import annotations

import copy

import httpx
import pytest
from typer.testing import CliRunner

pytest.importorskip("eth_account")

from conftest import VALID_PAYMENT_REQUIRED, encode_header

import x402_conformance.cli as cli
import x402_conformance.safety as safety
from x402_conformance.active import build_active_context, run_active_checks
from x402_conformance.checks.facilitator import run_facilitator_checks
from x402_conformance.payload_builder import EvmSigner
from x402_conformance.safety import DEFAULT_SAFETY_POLICY, SafetyViolation

TARGET = "https://api.example.com/premium-data"
FACILITATOR = "https://facilitator.example"
RPC = "http://rpc.local"
SIGNER = EvmSigner.from_key("0x" + "77" * 32)
REDIRECTS = (301, 302, 303, 307, 308)


def _required(network: str = "eip155:84532") -> dict:
    document = copy.deepcopy(VALID_PAYMENT_REQUIRED)
    document["accepts"][0]["network"] = network
    return document


@pytest.mark.parametrize(
    "network", ["eip155:1337", "eip155:31337", "eip155:84532", "eip155:11155111"]
)
def test_explicit_evm_testnet_and_local_allowlist(network: str) -> None:
    assert DEFAULT_SAFETY_POLICY.require_safe_network(network) == network


@pytest.mark.parametrize(
    "network",
    [
        "eip155:1",
        "eip155:8453",
        "eip155:137",
        "eip155:999999",
        "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
        "cosmos:cosmoshub-4",
        "base-sepolia",
    ],
)
def test_mainnet_and_unknown_networks_fail_closed(network: str) -> None:
    with pytest.raises(SafetyViolation, match="allowlist|unsupported|CAIP-2"):
        DEFAULT_SAFETY_POLICY.require_safe_network(network)


def test_solana_future_driver_policy_allows_only_non_mainnet() -> None:
    assert (
        DEFAULT_SAFETY_POLICY.require_safe_network("solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1")
        == "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
    )


def test_rpc_chain_must_match_advertised_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(safety, "read_rpc_chain_id", lambda _url: 84532)
    assert DEFAULT_SAFETY_POLICY.require_matching_rpc("eip155:84532", RPC) == 84532

    monkeypatch.setattr(safety, "read_rpc_chain_id", lambda _url: 1)
    with pytest.raises(SafetyViolation, match="RPC chain mismatch"):
        DEFAULT_SAFETY_POLICY.require_matching_rpc("eip155:84532", RPC)


def test_rpc_is_mandatory_for_settlement() -> None:
    with pytest.raises(SafetyViolation, match="rpc-url"):
        DEFAULT_SAFETY_POLICY.require_matching_rpc("eip155:84532", None)


@pytest.mark.parametrize("status", REDIRECTS)
def test_rpc_redirects_are_never_followed(monkeypatch: pytest.MonkeyPatch, status: int) -> None:
    calls: list[str] = []

    def fake_post(url: str, **_kwargs: object) -> httpx.Response:
        calls.append(url)
        return httpx.Response(status, headers={"Location": "https://evil.example/rpc"})

    monkeypatch.setattr(safety.httpx, "post", fake_post)
    with pytest.raises(SafetyViolation, match="redirect blocked"):
        safety.read_rpc_chain_id("https://rpc.example")
    assert calls == ["https://rpc.example"]


def test_mainnet_active_target_is_rejected_before_payment_request() -> None:
    payment_requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal payment_requests
        if request.headers.get("PAYMENT-SIGNATURE"):
            payment_requests += 1
        return httpx.Response(
            402, headers={"PAYMENT-REQUIRED": encode_header(_required("eip155:1"))}
        )

    with pytest.raises(SafetyViolation, match="allowlist"):
        run_active_checks(TARGET, SIGNER, transport=httpx.MockTransport(handler))
    assert payment_requests == 0


def test_mainnet_facilitator_resource_is_rejected_before_verify_or_settle() -> None:
    payment_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal payment_calls
        if request.url.path in {"/verify", "/settle"}:
            payment_calls += 1
        return httpx.Response(
            402, headers={"PAYMENT-REQUIRED": encode_header(_required("eip155:8453"))}
        )

    with pytest.raises(SafetyViolation, match="allowlist"):
        run_facilitator_checks(
            FACILITATOR,
            resource_url=TARGET,
            signer=SIGNER,
            allow_settle=True,
            rpc_url=RPC,
            transport=httpx.MockTransport(handler),
        )
    assert payment_calls == 0


@pytest.mark.parametrize("status", REDIRECTS)
@pytest.mark.parametrize(
    "location",
    [
        "https://api.example.com/new-path",
        "https://evil.example/collect",
        "http://api.example.com/downgrade",
    ],
)
def test_active_payment_material_never_crosses_redirect(status: int, location: str) -> None:
    redirected_headers: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "evil.example" or request.url.path in {"/new-path", "/downgrade"}:
            redirected_headers.append(request.headers.get("PAYMENT-SIGNATURE"))
            return httpx.Response(200)
        if request.headers.get("PAYMENT-SIGNATURE") is None:
            return httpx.Response(
                402, headers={"PAYMENT-REQUIRED": encode_header(VALID_PAYMENT_REQUIRED)}
            )
        return httpx.Response(status, headers={"Location": location})

    # Deliberately give the externally-created client follow_redirects=True.  The
    # payment sender must override it per request.
    with httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True) as client:
        context = build_active_context(client, TARGET, "GET", SIGNER)
        assert context is not None
        response = context.send_header("signed-payment-material")

    assert response.status_code == status
    assert response.redirect_blocked == f"payment redirect blocked (HTTP {status})"
    assert redirected_headers == []


@pytest.mark.parametrize("status", REDIRECTS)
@pytest.mark.parametrize("path", ["verify", "settle"])
def test_facilitator_payment_bodies_never_cross_redirect(
    monkeypatch: pytest.MonkeyPatch, status: int, path: str
) -> None:
    evil_bodies: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "evil.example":
            evil_bodies.append(request.content)
            return httpx.Response(200, json={})
        if request.url.host == "api.example.com":
            return httpx.Response(
                402, headers={"PAYMENT-REQUIRED": encode_header(VALID_PAYMENT_REQUIRED)}
            )
        if request.url.path == f"/{path}":
            return httpx.Response(status, headers={"Location": "https://evil.example/collect"})
        if request.url.path == "/supported":
            return httpx.Response(404)
        return httpx.Response(200, json={"isValid": False, "invalidReason": "invalid_payment"})

    monkeypatch.setattr(safety, "read_rpc_chain_id", lambda _url: 84532)
    run_facilitator_checks(
        FACILITATOR,
        resource_url=TARGET,
        signer=SIGNER,
        allow_settle=path == "settle",
        rpc_url=RPC if path == "settle" else None,
        transport=httpx.MockTransport(handler),
    )
    assert evil_bodies == []


def test_cli_mainnet_failure_happens_before_signer_creation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli, "run_checks", lambda *_a, **_k: [])
    monkeypatch.setattr(
        "x402_conformance.active.preflight_resource_network",
        lambda *_a, **_k: (_ for _ in ()).throw(SafetyViolation("mainnet denied")),
    )

    def signer_must_not_run(_key: str | None) -> object:
        raise AssertionError("signer was created before the safety preflight")

    monkeypatch.setattr(cli, "_make_signer", signer_must_not_run)
    result = CliRunner().invoke(cli.app, ["check", TARGET, "--active"])
    assert result.exit_code == 2
    assert "payment safety check failed" in result.output
    assert not isinstance(result.exception, AssertionError)
