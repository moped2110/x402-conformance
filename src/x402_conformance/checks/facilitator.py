"""FA: facilitator conformance checks (catalog §6).

A facilitator is the service a resource server delegates payment verification
and settlement to. It exposes ``GET /supported``, ``POST /verify`` and
``POST /settle`` (CORE §7). This group checks them black-box.

What runs without a chain (this session):
- FA-SUP-001/002: ``/supported`` schema + CAIP-2 kinds (pure GET, passive).
- FA-VER-002: ``/verify`` with deliberately-invalid payloads must return
  ``isValid: false`` with a spec error code (signature/amount/recipient/time
  all reject pre-RPC). Needs a ``--resource`` to source real requirements.
- FA-ERR-001: ``invalidReason`` values are from the CORE §9 registry.

Deferred to on-chain day (need RPC / funded payer):
- FA-VER-001 (valid payload → isValid:true; a real facilitator checks balance),
- FA-SET-001/002, FA-SET-003 (double-settle / nonce).

Driven explicitly by ``run_facilitator_checks``; not part of the passive REGISTRY.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx

from ..probe import build_probe
from .base import CheckResult, Severity, Status

_CORE = "x402-specification-v2.md"

# CORE §9 error code registry — invalidReason / errorReason must come from here.
KNOWN_ERROR_CODES = frozenset({
    "insufficient_funds",
    "invalid_exact_evm_payload_authorization_valid_after",
    "invalid_exact_evm_payload_authorization_valid_before",
    "invalid_exact_evm_payload_authorization_value_mismatch",
    "invalid_exact_evm_payload_signature",
    "invalid_exact_evm_payload_recipient_mismatch",
    "invalid_network",
    "invalid_payload",
    "invalid_payment_requirements",
    "invalid_scheme",
    "unsupported_scheme",
    "invalid_x402_version",
    "invalid_transaction_state",
    "unexpected_verify_error",
    "unexpected_settle_error",
})

_CAIP2 = __import__("re").compile(r"^[a-z0-9-]{3,8}:[-_a-zA-Z0-9]{1,32}$")


@dataclass
class FacilitatorContext:
    base_url: str
    client: httpx.Client
    requirements: dict[str, Any] | None  # eip3009 reqs from --resource, if any
    signer: Any | None
    supported: dict[str, Any] | None = None  # cached /supported body


FaFunc = Callable[[FacilitatorContext], "tuple[Status, str]"]


@dataclass(frozen=True)
class _FaCheck:
    check_id: str
    title: str
    severity: Severity
    spec_ref: str
    func: FaFunc


FA_REGISTRY: list[_FaCheck] = []


def _register(cid: str, title: str, sev: Severity, ref: str) -> Callable[[FaFunc], FaFunc]:
    def deco(f: FaFunc) -> FaFunc:
        FA_REGISTRY.append(_FaCheck(cid, title, sev, ref, f))
        return f

    return deco


def _get_supported(ctx: FacilitatorContext) -> dict[str, Any] | None:
    if ctx.supported is not None:
        return ctx.supported
    try:
        resp = ctx.client.get(f"{ctx.base_url.rstrip('/')}/supported")
        ctx.supported = resp.json() if resp.status_code == 200 else None
    except Exception:
        ctx.supported = None
    return ctx.supported


@_register("FA-SUP-001", "/supported returns kinds[], extensions[], signers{}", Severity.MAJOR,
           f"{_CORE} §7.3")
def fa_sup_001(ctx: FacilitatorContext) -> tuple[Status, str]:
    body = _get_supported(ctx)
    if body is None:
        return Status.FAIL, "GET /supported did not return 200 with JSON"
    missing = [k for k in ("kinds", "extensions", "signers") if k not in body]
    if missing:
        return Status.FAIL, f"/supported missing keys: {', '.join(missing)}"
    if not isinstance(body["kinds"], list) or not isinstance(body["signers"], dict):
        return Status.FAIL, "kinds must be array, signers must be object"
    return Status.PASS, ""


@_register("FA-SUP-002", "Each supported kind has x402Version, scheme, CAIP-2 network",
           Severity.MAJOR, f"{_CORE} §7.3.1")
def fa_sup_002(ctx: FacilitatorContext) -> tuple[Status, str]:
    body = _get_supported(ctx)
    if body is None or not isinstance(body.get("kinds"), list):
        return Status.SKIP, "no valid /supported.kinds to inspect"
    problems = []
    for i, kind in enumerate(body["kinds"]):
        if not isinstance(kind, dict):
            problems.append(f"kinds[{i}] not an object")
            continue
        if kind.get("x402Version") != 2:
            problems.append(f"kinds[{i}].x402Version != 2")
        if not kind.get("scheme"):
            problems.append(f"kinds[{i}].scheme missing")
        net = kind.get("network")
        if not (isinstance(net, str) and _CAIP2.match(net)):
            problems.append(f"kinds[{i}].network {net!r} not CAIP-2")
    if problems:
        return Status.FAIL, "; ".join(problems[:6])
    return Status.PASS, ""


def _verify(ctx: FacilitatorContext, payload: dict[str, Any], requirements: dict[str, Any]) -> dict[str, Any] | None:
    req = {"x402Version": 2, "paymentPayload": payload, "paymentRequirements": requirements}
    try:
        resp = ctx.client.post(f"{ctx.base_url.rstrip('/')}/verify", json=req)
        data: Any = json.loads(resp.text)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


@_register("FA-VER-002", "/verify rejects invalid payloads with isValid:false", Severity.CRITICAL,
           f"{_CORE} §7.1, §9")
def fa_ver_002(ctx: FacilitatorContext) -> tuple[Status, str]:
    if ctx.requirements is None or ctx.signer is None:
        return Status.SKIP, "no --resource requirements / signer to build a payment"
    from ..payload_builder import build_exact_eip3009_payload

    # Validly sign for a token amount but verify against the REAL requirements:
    # the facilitator must reject value != requirements.amount. A post-signing
    # tamper would be caught by the signature check instead, masking an
    # amount-validation gap — so we re-sign (cf. RS-NEG-013).
    cheap = build_exact_eip3009_payload({**ctx.requirements, "amount": "1"}, ctx.signer)
    result = _verify(ctx, cheap, ctx.requirements)
    if result is None:
        return Status.FAIL, "/verify did not return JSON"
    if result.get("isValid") is True:
        return Status.FAIL, "/verify reported isValid:true for value != requirements.amount"
    return Status.PASS, f"correctly invalid (reason: {result.get('invalidReason')!r})"


@_register("FA-ERR-001", "invalidReason is from the CORE §9 error registry", Severity.MINOR,
           f"{_CORE} §9")
def fa_err_001(ctx: FacilitatorContext) -> tuple[Status, str]:
    if ctx.requirements is None or ctx.signer is None:
        return Status.SKIP, "no --resource requirements / signer to trigger an error"
    from ..payload_builder import build_exact_eip3009_payload

    cheap = build_exact_eip3009_payload({**ctx.requirements, "amount": "1"}, ctx.signer)
    result = _verify(ctx, cheap, ctx.requirements)
    if result is None:
        return Status.SKIP, "no /verify JSON to inspect"
    reason = result.get("invalidReason")
    if reason is None:
        return Status.FAIL, "isValid:false without an invalidReason"
    if reason not in KNOWN_ERROR_CODES:
        return Status.FAIL, f"invalidReason {reason!r} not in the CORE §9 registry"
    return Status.PASS, f"reason {reason!r} is a known code"


def evaluate_facilitator(ctx: FacilitatorContext | None) -> list[CheckResult]:
    results: list[CheckResult] = []
    for check in FA_REGISTRY:
        if ctx is None:
            status, detail = Status.SKIP, "facilitator unreachable"
        else:
            try:
                status, detail = check.func(ctx)
            except Exception as exc:
                status, detail = Status.ERROR, f"check crashed (suite bug): {exc!r}"
        results.append(CheckResult(check.check_id, check.title, check.severity,
                                   check.spec_ref, status, detail))
    return results


def run_facilitator_checks(
    base_url: str,
    resource_url: str | None = None,
    signer: Any | None = None,
    timeout: float = 10.0,
    transport: httpx.BaseTransport | None = None,
) -> list[CheckResult]:
    """Probe a facilitator. If resource_url is given, also exercise /verify."""
    headers = {"User-Agent": "x402-conformance/0.0.1 (facilitator)"}
    with httpx.Client(timeout=timeout, transport=transport, headers=headers,
                      follow_redirects=True) as client:
        requirements = None
        if resource_url is not None:
            from ..active import choose_eip3009_requirement
            probe = build_probe(client.request("GET", resource_url))
            requirements = choose_eip3009_requirement(probe.raw)
        ctx = FacilitatorContext(base_url=base_url, client=client,
                                 requirements=requirements, signer=signer)
        return evaluate_facilitator(ctx)
