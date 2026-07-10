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

from .. import USER_AGENT
from ..probe import build_probe
from .base import CheckResult, Severity, Status

_CORE = "x402-specification-v2.md"

# Canonical error-reason vocabulary, vendored verbatim from the TS `ErrorReasons`
# enum in typescript/packages/legacy/x402/src/types/verify/x402Specs.ts — the
# machine-enforced source (reference SDK runs `z.enum(ErrorReasons)` on
# SettleResponse.errorReason / VerifyResponse.invalidReason / x402Response.error).
# Re-sync on every SPEC_BASELINE bump; tests/test_error_reason_drift.py compares
# this set against a live x402Specs.ts when one is reachable (skips otherwise).
SPEC_ERROR_REASONS = frozenset(
    {
        "insufficient_funds",
        "invalid_exact_evm_payload_authorization_valid_after",
        "invalid_exact_evm_payload_authorization_valid_before",
        "invalid_exact_evm_payload_authorization_value",
        # Adopted into the TS ErrorReasons enum upstream (previously TS-missing, our
        # T-20 nit) — now a first-class spec code, moved out of _LOCAL_ERROR_CODES.
        "invalid_exact_evm_payload_authorization_value_mismatch",
        "invalid_exact_evm_payload_signature",
        "invalid_exact_evm_payload_undeployed_smart_wallet",
        "invalid_exact_evm_payload_recipient_mismatch",
        "invalid_exact_svm_payload_transaction",
        "invalid_exact_svm_payload_transaction_amount_mismatch",
        "invalid_exact_svm_payload_transaction_create_ata_instruction",
        "invalid_exact_svm_payload_transaction_create_ata_instruction_incorrect_payee",
        "invalid_exact_svm_payload_transaction_create_ata_instruction_incorrect_asset",
        "invalid_exact_svm_payload_transaction_instructions",
        "invalid_exact_svm_payload_transaction_instructions_length",
        "invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction",
        "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction",
        "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction_too_high",
        "invalid_exact_svm_payload_transaction_instruction_not_spl_token_transfer_checked",
        "invalid_exact_svm_payload_transaction_instruction_not_token_2022_transfer_checked",
        "invalid_exact_svm_payload_transaction_fee_payer_included_in_instruction_accounts",
        "invalid_exact_svm_payload_transaction_fee_payer_transferring_funds",
        "invalid_exact_svm_payload_transaction_not_a_transfer_instruction",
        "invalid_exact_svm_payload_transaction_receiver_ata_not_found",
        "invalid_exact_svm_payload_transaction_sender_ata_not_found",
        "invalid_exact_svm_payload_transaction_simulation_failed",
        "invalid_exact_svm_payload_transaction_transfer_to_incorrect_ata",
        "invalid_network",
        "invalid_payload",
        "invalid_payment_requirements",
        "invalid_scheme",
        "invalid_payment",
        "payment_expired",
        "unsupported_scheme",
        "invalid_x402_version",
        "invalid_transaction_state",
        "settle_exact_svm_block_height_exceeded",
        "settle_exact_svm_transaction_confirmation_timed_out",
        "unexpected_settle_error",
        "unexpected_verify_error",
        "duplicate_settlement",
    }
)

# Codes we recognise beyond the TS `ErrorReasons` Zod enum:
#  - asset_not_deployed_contract: proposed in x402#2554 (asset address is an EOA,
#    no bytecode) — not yet in the enum.
# (..._authorization_value_mismatch used to live here while the TS enum lacked it;
#  upstream has since adopted it, so it now sits in SPEC_ERROR_REASONS above.)
_LOCAL_ERROR_CODES = frozenset(
    {
        "asset_not_deployed_contract",
    }
)

# CORE §9 / spec ErrorReasons registry — invalidReason / errorReason must come from here.
KNOWN_ERROR_CODES = SPEC_ERROR_REASONS | _LOCAL_ERROR_CODES

_CAIP2 = __import__("re").compile(r"^[a-z0-9-]{3,8}:[-_a-zA-Z0-9]{1,32}$")

# A well-known EOA (Anvil dev account #0): no contract code on any chain, so it
# can never be a token. Used to probe the asset_not_deployed_contract guard (x402#2554).
_EOA_ASSET = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"


@dataclass
class FacilitatorContext:
    base_url: str
    client: httpx.Client
    requirements: dict[str, Any] | None  # eip3009 reqs from --resource, if any
    signer: Any | None
    supported: dict[str, Any] | None = None  # cached /supported body
    supported_status: int | None = None  # last GET /supported status (None = unreachable)
    allow_settle: bool = False  # FA-SET moves real funds; opt-in only


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
    except Exception:
        ctx.supported_status = None  # unreachable / transport error
        return None
    ctx.supported_status = resp.status_code
    if resp.status_code != 200:
        return None  # absent (e.g. 404) — /supported is optional (CORE §7.3)
    try:
        body = resp.json()
    except Exception:
        return None  # 200 but not JSON (status recorded as 200 → a real fault)
    ctx.supported = body if isinstance(body, dict) else None
    return ctx.supported


@_register(
    "FA-SUP-001",
    "/supported (if present) returns kinds[], extensions[], signers{}",
    Severity.MAJOR,
    f"{_CORE} §7.3",
)
def fa_sup_001(ctx: FacilitatorContext) -> tuple[Status, str]:
    body = _get_supported(ctx)
    if body is None:
        # /supported is OPTIONAL (CORE §7.3): a facilitator may omit it and still be
        # fully conformant — the payment requirements are carried inline in the 402
        # challenge. So an absent endpoint is a SKIP, not a failure. Only a present
        # but malformed /supported (200 + non-JSON, or missing keys) is a real fault.
        st = ctx.supported_status
        if st is None or st != 200:
            where = "unreachable" if st is None else f"HTTP {st}"
            return Status.SKIP, (
                f"/supported not implemented ({where}) — optional per CORE §7.3; "
                "the endpoint is testable from the inline 402 requirements"
            )
        return Status.FAIL, "GET /supported returned 200 but not a JSON object"
    missing = [k for k in ("kinds", "extensions", "signers") if k not in body]
    if missing:
        return Status.FAIL, f"/supported present but missing keys: {', '.join(missing)}"
    if not isinstance(body["kinds"], list) or not isinstance(body["signers"], dict):
        return Status.FAIL, "kinds must be array, signers must be object"
    return Status.PASS, ""


@_register(
    "FA-SUP-002",
    "Each supported kind is well-formed (x402Version 1/2, scheme; v2 network is CAIP-2)",
    Severity.MAJOR,
    f"{_CORE} §7.3.1",
)
def fa_sup_002(ctx: FacilitatorContext) -> tuple[Status, str]:
    body = _get_supported(ctx)
    if body is None or not isinstance(body.get("kinds"), list):
        return Status.SKIP, "no valid /supported.kinds to inspect"
    problems = []
    for i, kind in enumerate(body["kinds"]):
        if not isinstance(kind, dict):
            problems.append(f"kinds[{i}] not an object")
            continue
        ver = kind.get("x402Version")
        if ver not in (1, 2):
            problems.append(f"kinds[{i}].x402Version {ver!r} is not 1 or 2")
        if not kind.get("scheme"):
            problems.append(f"kinds[{i}].scheme missing")
        net = kind.get("network")
        if not isinstance(net, str) or not net:
            problems.append(f"kinds[{i}].network missing")
        elif ver == 2 and not _CAIP2.match(net):
            # v2 networks are CAIP-2 (eip155:8453); a v1 kind legitimately carries a
            # legacy network *name* (e.g. "base-sepolia"), so CAIP-2 is required for v2
            # kinds only — a facilitator that serves both versions is conformant.
            problems.append(f"kinds[{i}].network {net!r} not CAIP-2 (required for v2)")
    if problems:
        return Status.FAIL, "; ".join(problems[:6])
    return Status.PASS, ""


def _verify(
    ctx: FacilitatorContext, payload: dict[str, Any], requirements: dict[str, Any]
) -> dict[str, Any] | None:
    req = {"x402Version": 2, "paymentPayload": payload, "paymentRequirements": requirements}
    try:
        resp = ctx.client.post(f"{ctx.base_url.rstrip('/')}/verify", json=req)
        data: Any = json.loads(resp.text)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _verify_raw(
    ctx: FacilitatorContext, payload: dict[str, Any], requirements: dict[str, Any]
) -> tuple[int | None, dict[str, Any] | None]:
    """Like `_verify`, but also returns the HTTP status code (for FA-VER-004).

    Returns ``(status_code, parsed_body_or_None)``; ``(None, None)`` if the request
    could not be sent at all.
    """
    req = {"x402Version": 2, "paymentPayload": payload, "paymentRequirements": requirements}
    try:
        resp = ctx.client.post(f"{ctx.base_url.rstrip('/')}/verify", json=req)
    except Exception:
        return None, None
    try:
        data: Any = json.loads(resp.text)
    except Exception:
        data = None
    return resp.status_code, (data if isinstance(data, dict) else None)


@_register(
    "FA-VER-002",
    "/verify rejects invalid payloads with isValid:false",
    Severity.CRITICAL,
    f"{_CORE} §7.1, §9",
)
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


@_register(
    "FA-VER-003",
    "/verify rejects an asset that is not a deployed contract (EOA)",
    Severity.CRITICAL,
    f"{_CORE} §7.1 + x402#2554 asset_not_deployed_contract",
)
def fa_ver_003(ctx: FacilitatorContext) -> tuple[Status, str]:
    if ctx.requirements is None or ctx.signer is None:
        return Status.SKIP, "no --resource requirements / signer to build a payment"
    if str(ctx.requirements.get("asset", "")).lower() == _EOA_ASSET.lower():
        return Status.SKIP, "endpoint already advertises the EOA test asset"
    from ..payload_builder import build_exact_eip3009_payload

    # An asset pointing at an EOA has no bytecode; on-chain simulation does not
    # revert, so a facilitator that skips an eth_getCode pre-flight would settle a
    # silent no-op. /verify must report isValid:false (ideally asset_not_deployed_contract).
    eoa_req = {**ctx.requirements, "asset": _EOA_ASSET}
    payload = build_exact_eip3009_payload(eoa_req, ctx.signer)
    result = _verify(ctx, payload, eoa_req)
    if result is None:
        return Status.FAIL, "/verify did not return JSON"
    if result.get("isValid") is True:
        return Status.FAIL, (
            "/verify accepted a payment whose asset is an EOA (no contract code) — "
            "silent-no-op / payment-bypass risk"
        )
    reason = result.get("invalidReason")
    note = (
        ""
        if reason == "asset_not_deployed_contract"
        else (f" (reason {reason!r}; canonical is asset_not_deployed_contract)")
    )
    return Status.PASS, f"correctly rejected EOA asset{note}"


@_register(
    "FA-VER-004",
    "/verify handles an invalid payment with a clean 4xx, not a 5xx server error",
    Severity.MINOR,
    f"{_CORE} §7.1",
)
def fa_ver_004(ctx: FacilitatorContext) -> tuple[Status, str]:
    if ctx.requirements is None or ctx.signer is None:
        return Status.SKIP, "no --resource requirements / signer to build a payment"
    if str(ctx.requirements.get("asset", "")).lower() == _EOA_ASSET.lower():
        return Status.SKIP, "endpoint already advertises the EOA test asset"
    from ..payload_builder import build_exact_eip3009_payload

    # A client-supplied asset that is an EOA (no bytecode) is invalid input. A robust
    # facilitator reports isValid:false (HTTP 200 or a 4xx). A 5xx means an unhandled
    # server error on client-controlled input — a robustness gap seen on real
    # facilitators that let a balanceOf/parse exception bubble up to a 500. MINOR: the
    # rejection itself is what FA-VER-003 gates; this only flags the *shape* of it.
    eoa_req = {**ctx.requirements, "asset": _EOA_ASSET}
    payload = build_exact_eip3009_payload(eoa_req, ctx.signer)
    status, _ = _verify_raw(ctx, payload, eoa_req)
    if status is None:
        return Status.SKIP, "/verify unreachable — no response to inspect"
    if 500 <= status <= 599:
        return Status.FAIL, (
            f"/verify returned HTTP {status} on an invalid (EOA-asset) payment — malformed "
            "client input should surface as isValid:false (200/4xx), not a server error"
        )
    return Status.PASS, f"clean HTTP {status} on invalid input (no 5xx)"


@_register(
    "FA-ERR-001", "invalidReason is from the CORE §9 error registry", Severity.MINOR, f"{_CORE} §9"
)
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


def _settle(
    ctx: FacilitatorContext, payload: dict[str, Any], requirements: dict[str, Any]
) -> dict[str, Any] | None:
    req = {"x402Version": 2, "paymentPayload": payload, "paymentRequirements": requirements}
    try:
        resp = ctx.client.post(f"{ctx.base_url.rstrip('/')}/settle", json=req)
        data: Any = json.loads(resp.text)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def evaluate_settle(ctx: FacilitatorContext) -> list[CheckResult]:
    """FA-SET: direct /settle tests. Moves REAL funds; runs only when allow_settle."""
    ids = {
        "FA-SET-001": (
            "/settle of a valid payment succeeds with a tx hash",
            Severity.MAJOR,
            f"{_CORE} §7.2",
        ),
        "FA-SET-002": (
            "/settle of an invalid payment fails with empty tx",
            Severity.MAJOR,
            f"{_CORE} §7.2",
        ),
        "FA-SET-003": (
            "Double-settle of the same payment is rejected (nonce reuse)",
            Severity.CRITICAL,
            f"{_CORE} §10.1",
        ),
    }

    def mk(cid: str, status: Status, detail: str = "") -> CheckResult:
        title, sev, ref = ids[cid]
        return CheckResult(cid, title, sev, ref, status, detail)

    if not ctx.allow_settle:
        return [
            mk(c, Status.SKIP, "pass --settle to run /settle tests (moves real funds)") for c in ids
        ]
    if ctx.requirements is None or ctx.signer is None:
        return [mk(c, Status.SKIP, "no --resource requirements / signer") for c in ids]

    from ..payload_builder import build_exact_eip3009_payload

    results: list[CheckResult] = []

    # FA-SET-001 — valid settle (a real on-chain settlement)
    good = build_exact_eip3009_payload(ctx.requirements, ctx.signer)
    r1 = _settle(ctx, good, ctx.requirements)
    if r1 is None:
        results.append(mk("FA-SET-001", Status.FAIL, "/settle did not return JSON"))
    elif r1.get("success") is True and r1.get("transaction") and r1["transaction"] != "0x":
        results.append(mk("FA-SET-001", Status.PASS, f"tx {r1['transaction']}"))
    else:
        results.append(
            mk("FA-SET-001", Status.FAIL, f"valid /settle did not succeed: {str(r1)[:160]}")
        )

    # FA-SET-003 — double-settle the SAME payment must be rejected
    if r1 and r1.get("success") is True:
        r3 = _settle(ctx, good, ctx.requirements)
        if r3 is not None and r3.get("success") is True:
            results.append(
                mk(
                    "FA-SET-003",
                    Status.FAIL,
                    "second settle of the same payment succeeded — nonce reuse not prevented",
                )
            )
        else:
            results.append(
                mk(
                    "FA-SET-003",
                    Status.PASS,
                    f"double-settle rejected (reason {(r3 or {}).get('errorReason')!r})",
                )
            )
    else:
        results.append(mk("FA-SET-003", Status.SKIP, "first settle did not succeed"))

    # FA-SET-002 — invalid settle (value != requirements) must fail with empty tx
    cheap = build_exact_eip3009_payload({**ctx.requirements, "amount": "1"}, ctx.signer)
    r2 = _settle(ctx, cheap, ctx.requirements)
    if r2 is None:
        results.append(mk("FA-SET-002", Status.FAIL, "/settle did not return JSON"))
    elif r2.get("success") is True:
        results.append(mk("FA-SET-002", Status.FAIL, "/settle succeeded for an invalid payment"))
    elif r2.get("transaction"):
        results.append(
            mk("FA-SET-002", Status.FAIL, "failed settle still carries a non-empty tx hash")
        )
    else:
        results.append(
            mk("FA-SET-002", Status.PASS, f"correctly failed (reason {r2.get('errorReason')!r})")
        )

    return results


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
        results.append(
            CheckResult(check.check_id, check.title, check.severity, check.spec_ref, status, detail)
        )
    return results


def run_facilitator_checks(
    base_url: str,
    resource_url: str | None = None,
    signer: Any | None = None,
    allow_settle: bool = False,
    timeout: float = 30.0,
    transport: httpx.BaseTransport | None = None,
) -> list[CheckResult]:
    """Probe a facilitator. If resource_url is given, also exercise /verify;
    with allow_settle, also run the FA-SET /settle tests (moves real funds)."""
    headers = {"User-Agent": USER_AGENT}
    with httpx.Client(
        timeout=timeout, transport=transport, headers=headers, follow_redirects=True
    ) as client:
        requirements = None
        if resource_url is not None:
            from ..active import choose_eip3009_requirement

            probe = build_probe(client.request("GET", resource_url))
            requirements = choose_eip3009_requirement(probe.raw)
        ctx = FacilitatorContext(
            base_url=base_url,
            client=client,
            requirements=requirements,
            signer=signer,
            allow_settle=allow_settle,
        )
        return evaluate_facilitator(ctx) + evaluate_settle(ctx)
