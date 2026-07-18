"""Safety-critical tests for the Anvil on-chain facilitator harness."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

pytest.importorskip("eth_account")
pytest.importorskip("web3")

from x402_conformance.payload_builder import EvmSigner, build_exact_eip3009_payload

_TOOL = Path(__file__).resolve().parents[1] / "tools" / "onchain_facilitator.py"
_TOKEN = "0x1111111111111111111111111111111111111111"


@pytest.fixture
def harness(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    monkeypatch.setenv("X402_TOKEN", _TOKEN)
    spec = importlib.util.spec_from_file_location("onchain_facilitator_under_test", _TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _Call:
    def __init__(self, value: object, calls: list[str], label: str) -> None:
        self.value = value
        self.calls = calls
        self.label = label

    def call(self, *_args: object, **_kwargs: object) -> object:
        self.calls.append(self.label)
        return self.value


class _Functions:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    def balanceOf(self, *_args: object) -> _Call:  # noqa: N802
        return _Call(10**9, self.calls, "balance")

    def authorizationState(self, *_args: object) -> _Call:  # noqa: N802
        return _Call(False, self.calls, "nonce")

    def transferWithAuthorization(self, *_args: object) -> _Call:  # noqa: N802
        return _Call(None, self.calls, "simulate")


class _Token:
    def __init__(self, calls: list[str]) -> None:
        self.functions = _Functions(calls)


def _payload(harness: ModuleType) -> dict[str, Any]:
    signer = EvmSigner.from_key("0x" + "44" * 32)
    return build_exact_eip3009_payload(harness.REQ, signer)


def test_verify_rejects_an_invalid_signature_before_simulation(
    harness: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(harness, "token", _Token(calls))
    payload = _payload(harness)
    signature = payload["payload"]["signature"]
    broken = "0x00" + signature[4:]

    result = harness.verify(payload["payload"]["authorization"], broken)

    assert result["isValid"] is False
    assert result["invalidReason"] == "invalid_exact_evm_payload_signature"
    assert calls == []


def test_verify_simulates_without_building_or_sending_a_transaction(
    harness: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(harness, "token", _Token(calls))
    payload = _payload(harness)

    result = harness.verify(payload["payload"]["authorization"], payload["payload"]["signature"])

    assert result == {"isValid": True, "payer": payload["payload"]["authorization"]["from"]}
    assert calls == ["balance", "nonce", "simulate"]
