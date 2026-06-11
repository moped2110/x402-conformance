"""Active probing: send (tampered) payments and observe the endpoint's response.

Passive checks (RS-HS/RS-PR) only do unpaid GETs. The negative group (RS-NEG)
must actively construct payments and verify the endpoint *rejects* the invalid
ones. This module provides that capability, kept separate from the passive
runner so the default behaviour never sends a payment without explicit intent.

Active checks require the `[evm]` extra (signing) and a throwaway signer.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx

from .models import SettlementResponse
from .probe import build_probe

PAYMENT_SIGNATURE_HEADER = "PAYMENT-SIGNATURE"
PAYMENT_RESPONSE_HEADER = "payment-response"


@dataclass(frozen=True)
class ActiveResponse:
    """The endpoint's response to a (tampered) payment attempt."""

    status_code: int
    headers: dict[str, str]
    body: bytes
    settlement: SettlementResponse | None = None
    settlement_error: str | None = None

    @property
    def served_resource(self) -> bool:
        """True if the endpoint delivered content (2xx) — i.e. accepted the payment."""
        return 200 <= self.status_code < 300

    @property
    def settled_ok(self) -> bool:
        return self.settlement is not None and self.settlement.success


@dataclass
class ActiveContext:
    """Everything an active check needs to attack one endpoint."""

    resource_url: str
    method: str
    requirements: dict[str, Any]  # chosen exact/eip3009 accepts entry
    signer: Any  # EvmSigner
    send: Callable[[dict[str, Any]], ActiveResponse]
    send_header: Callable[[str], ActiveResponse]  # send a raw PAYMENT-SIGNATURE value
    notes: list[str] = field(default_factory=list)


def _b64_json(obj: dict[str, Any]) -> str:
    return base64.b64encode(json.dumps(obj).encode()).decode()


def parse_settlement(headers: dict[str, str]) -> tuple[SettlementResponse | None, str | None]:
    raw = headers.get(PAYMENT_RESPONSE_HEADER)
    if raw is None:
        return None, None
    try:
        decoded = base64.b64decode(raw, validate=True)
        data = json.loads(decoded)
        return SettlementResponse.model_validate(data), None
    except Exception as exc:  # malformed settlement header is itself a finding
        return None, f"unparseable PAYMENT-RESPONSE: {exc}"


def choose_eip3009_requirement(raw: dict[str, Any] | None) -> dict[str, Any] | None:
    """Pick an `exact`/eip3009 EVM accepts entry we can build a payment for."""
    if not raw:
        return None
    accepts = raw.get("accepts")
    if not isinstance(accepts, list):
        return None
    for entry in accepts:
        if not isinstance(entry, dict):
            continue
        if entry.get("scheme") != "exact":
            continue
        network = entry.get("network")
        if not (isinstance(network, str) and network.startswith("eip155:")):
            continue
        raw_extra = entry.get("extra")
        extra: dict[str, Any] = raw_extra if isinstance(raw_extra, dict) else {}
        if extra.get("assetTransferMethod", "eip3009") != "eip3009":
            continue
        if extra.get("name") and extra.get("version"):
            return entry
    return None


def _response_from(response: httpx.Response) -> ActiveResponse:
    headers = {k.lower(): v for k, v in response.headers.items()}
    settlement, settlement_error = parse_settlement(headers)
    return ActiveResponse(
        status_code=response.status_code,
        headers=headers,
        body=response.content,
        settlement=settlement,
        settlement_error=settlement_error,
    )


def build_active_context(
    client: httpx.Client,
    url: str,
    method: str,
    signer: Any,
) -> ActiveContext | None:
    """Probe the endpoint for requirements and wire up payment senders.

    Returns None if the endpoint offers no exact/eip3009 requirement we can pay.
    """
    probe = build_probe(client.request(method, url))
    requirements = choose_eip3009_requirement(probe.raw)
    if requirements is None:
        return None

    def send(payload: dict[str, Any]) -> ActiveResponse:
        return send_header(_b64_json(payload))

    def send_header(header_value: str) -> ActiveResponse:
        response = client.request(method, url, headers={PAYMENT_SIGNATURE_HEADER: header_value})
        return _response_from(response)

    return ActiveContext(
        resource_url=url,
        method=method,
        requirements=requirements,
        signer=signer,
        send=send,
        send_header=send_header,
    )


def run_active_checks(
    url: str,
    signer: Any,
    method: str = "GET",
    timeout: float = 10.0,
    transport: httpx.BaseTransport | None = None,
) -> list[Any]:
    """Run the RS-NEG active checks against `url`. Returns list[CheckResult]."""
    from .checks.negative import evaluate_active  # late import avoids cycle

    headers = {"User-Agent": "x402-conformance/0.0.1 (active)"}
    with httpx.Client(
        timeout=timeout, transport=transport, follow_redirects=True, headers=headers
    ) as client:
        context = build_active_context(client, url, method, signer)
        return evaluate_active(context)


def run_payment_checks(
    url: str,
    signer: Any,
    rpc_url: str | None = None,
    method: str = "GET",
    timeout: float = 30.0,
    transport: httpx.BaseTransport | None = None,
) -> list[Any]:
    """Run the RS-PAY positive settlement checks. MOVES REAL FUNDS — needs a
    funded signer. Returns list[CheckResult]."""
    from .checks.payment import evaluate_payment

    headers = {"User-Agent": "x402-conformance/0.0.1 (pay)"}
    with httpx.Client(
        timeout=timeout, transport=transport, follow_redirects=True, headers=headers
    ) as client:
        context = build_active_context(client, url, method, signer)
        return evaluate_payment(context, rpc_url)
