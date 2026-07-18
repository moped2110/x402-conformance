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

With explicit testnet/local settlement consent, a matching RPC, and a funded payer:
- FA-SET-001/002 and FA-SET-003 exercise valid, invalid, and duplicate settlement.
- FA-SET-001 reuses the exact on-chain Transfer verifier.

FA-VER-001 (valid payload → isValid:true with balance semantics) and the
state-change proof FA-VER-005 remain explicitly planned in the support matrix.

Driven explicitly by ``run_facilitator_checks``; not part of the passive REGISTRY.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, cast

import httpx
from pydantic import ValidationError

from .. import USER_AGENT
from ..models import SettlementResponse, SupportedResponse, VerifyResponse
from ..probe import build_probe
from ..safety import DEFAULT_SAFETY_POLICY
from .base import CheckResult, Severity, Status, append_unique_check

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
    resource_url: str | None = None
    extensions: dict[str, Any] | None = None
    rpc_url: str | None = None
    supported: dict[str, Any] | None = None  # cached /supported body
    supported_status: int | None = None  # last GET /supported status (None = unreachable)
    supported_error: str | None = None
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
    """Create a decorator that adds one uniquely identified facilitator check."""

    def deco(f: FaFunc) -> FaFunc:
        """Register the decorated facilitator check and return it unchanged."""
        append_unique_check(FA_REGISTRY, _FaCheck(cid, title, sev, ref, f), cid)
        return f

    return deco


def _build_payload(ctx: FacilitatorContext, requirements: dict[str, Any]) -> dict[str, Any]:
    """Build a resource-bound EIP-3009 payload from the facilitator check context."""
    from ..payload_builder import EvmSigner, build_exact_eip3009_payload

    return build_exact_eip3009_payload(
        requirements,
        cast(EvmSigner, ctx.signer),
        resource_url=ctx.resource_url,
        extensions=ctx.extensions,
    )


def _get_supported(ctx: FacilitatorContext) -> dict[str, Any] | None:
    """Fetch and strictly validate the facilitator's supported-capabilities response."""
    if ctx.supported is not None:
        return ctx.supported
    try:
        resp = ctx.client.get(f"{ctx.base_url.rstrip('/')}/supported")
    except httpx.HTTPError:
        ctx.supported_status = None
        raise
    ctx.supported_status = resp.status_code
    if resp.status_code != 200:
        return None  # absent (e.g. 404) — /supported is optional (CORE §7.3)
    try:
        body: Any = resp.json()
        parsed = SupportedResponse.model_validate(body)
    except (ValueError, ValidationError) as exc:
        ctx.supported_error = f"invalid /supported response: {exc}"
        return None  # 200 but not JSON (status recorded as 200 → a real fault)
    ctx.supported = parsed.model_dump(by_alias=True)
    return ctx.supported


@_register(
    "FA-SUP-001",
    "/supported (if present) returns kinds[], extensions[], signers{}",
    Severity.MAJOR,
    f"{_CORE} §7.3",
)
def fa_sup_001(ctx: FacilitatorContext) -> tuple[Status, str]:
    """Evaluate FA-SUP-001: /supported (if present) returns kinds[], extensions[], signers{}."""
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
        return Status.FAIL, ctx.supported_error or "GET /supported returned invalid JSON"
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
    """Evaluate FA-SUP-002: Each supported kind is well-formed (x402Version 1/2, scheme; v2 network is CAIP-2)."""
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
) -> tuple[VerifyResponse | None, str | None]:
    """Submit one payment payload to verify and classify its strict response."""
    req = {"x402Version": 2, "paymentPayload": payload, "paymentRequirements": requirements}
    try:
        resp = ctx.client.post(
            f"{ctx.base_url.rstrip('/')}/verify", json=req, follow_redirects=False
        )
    except httpx.HTTPError:
        raise
    if not 200 <= resp.status_code < 500:
        return None, f"/verify returned HTTP {resp.status_code}"
    try:
        data: Any = json.loads(resp.text)
        return VerifyResponse.model_validate(data), None
    except (ValueError, ValidationError) as exc:
        return None, f"/verify returned an invalid response: {exc}"


def _verify_raw(
    ctx: FacilitatorContext, payload: dict[str, Any], requirements: dict[str, Any]
) -> tuple[int | None, dict[str, Any] | None]:
    """Like `_verify`, but also returns the HTTP status code (for FA-VER-004).

    Returns ``(status_code, parsed_body_or_None)``; ``(None, None)`` if the request
    could not be sent at all.
    """
    req = {"x402Version": 2, "paymentPayload": payload, "paymentRequirements": requirements}
    try:
        resp = ctx.client.post(
            f"{ctx.base_url.rstrip('/')}/verify", json=req, follow_redirects=False
        )
    except httpx.HTTPError:
        raise
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
    """Evaluate FA-VER-002: /verify rejects invalid payloads with isValid:false."""
    if ctx.requirements is None or ctx.signer is None:
        return Status.SKIP, "no --resource requirements / signer to build a payment"
    # Validly sign for a token amount but verify against the REAL requirements:
    # the facilitator must reject value != requirements.amount. A post-signing
    # tamper would be caught by the signature check instead, masking an
    # amount-validation gap — so we re-sign (cf. RS-NEG-013).
    cheap = _build_payload(ctx, {**ctx.requirements, "amount": "1"})
    result, error = _verify(ctx, cheap, ctx.requirements)
    if result is None:
        return Status.FAIL, error or "/verify did not return a valid response"
    if result.is_valid:
        return Status.FAIL, "/verify reported isValid:true for value != requirements.amount"
    return Status.PASS, f"correctly invalid (reason: {result.invalid_reason!r})"


@_register(
    "FA-VER-003",
    "/verify rejects an asset that is not a deployed contract (EOA)",
    Severity.CRITICAL,
    f"{_CORE} §7.1 + x402#2554 asset_not_deployed_contract",
)
def fa_ver_003(ctx: FacilitatorContext) -> tuple[Status, str]:
    """Evaluate FA-VER-003: /verify rejects an asset that is not a deployed contract (EOA)."""
    if ctx.requirements is None or ctx.signer is None:
        return Status.SKIP, "no --resource requirements / signer to build a payment"
    if str(ctx.requirements.get("asset", "")).lower() == _EOA_ASSET.lower():
        return Status.SKIP, "endpoint already advertises the EOA test asset"
    # An asset pointing at an EOA has no bytecode; on-chain simulation does not
    # revert, so a facilitator that skips an eth_getCode pre-flight would settle a
    # silent no-op. /verify must report isValid:false (ideally asset_not_deployed_contract).
    eoa_req = {**ctx.requirements, "asset": _EOA_ASSET}
    payload = _build_payload(ctx, eoa_req)
    result, error = _verify(ctx, payload, eoa_req)
    if result is None:
        return Status.FAIL, error or "/verify did not return a valid response"
    if result.is_valid:
        return Status.FAIL, (
            "/verify accepted a payment whose asset is an EOA (no contract code) — "
            "silent-no-op / payment-bypass risk"
        )
    reason = result.invalid_reason
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
    """Evaluate FA-VER-004: /verify handles an invalid payment with a clean 4xx, not a 5xx server error."""
    if ctx.requirements is None or ctx.signer is None:
        return Status.SKIP, "no --resource requirements / signer to build a payment"
    if str(ctx.requirements.get("asset", "")).lower() == _EOA_ASSET.lower():
        return Status.SKIP, "endpoint already advertises the EOA test asset"
    # A client-supplied asset that is an EOA (no bytecode) is invalid input. A robust
    # facilitator reports isValid:false (HTTP 200 or a 4xx). A 5xx means an unhandled
    # server error on client-controlled input — a robustness gap seen on real
    # facilitators that let a balanceOf/parse exception bubble up to a 500. MINOR: the
    # rejection itself is what FA-VER-003 gates; this only flags the *shape* of it.
    eoa_req = {**ctx.requirements, "asset": _EOA_ASSET}
    payload = _build_payload(ctx, eoa_req)
    status, _ = _verify_raw(ctx, payload, eoa_req)
    if status is None:
        return Status.SKIP, "/verify unreachable — no response to inspect"
    if 500 <= status <= 599:
        return Status.FAIL, (
            f"/verify returned HTTP {status} on an invalid (EOA-asset) payment — malformed "
            "client input should surface as isValid:false (200/4xx), not a server error"
        )
    if not (200 <= status < 300 or 400 <= status < 500):
        return Status.FAIL, f"/verify returned unexpected HTTP {status}"
    return Status.PASS, f"clean HTTP {status} on invalid input (no 5xx)"


@_register(
    "FA-ERR-001", "invalidReason is from the CORE §9 error registry", Severity.MINOR, f"{_CORE} §9"
)
def fa_err_001(ctx: FacilitatorContext) -> tuple[Status, str]:
    """Evaluate FA-ERR-001: invalidReason is from the CORE §9 error registry."""
    if ctx.requirements is None or ctx.signer is None:
        return Status.SKIP, "no --resource requirements / signer to trigger an error"
    cheap = _build_payload(ctx, {**ctx.requirements, "amount": "1"})
    result, error = _verify(ctx, cheap, ctx.requirements)
    if result is None:
        return Status.FAIL, error or "no valid /verify response to inspect"
    reason = result.invalid_reason
    if reason is None:
        return Status.FAIL, "isValid:false without an invalidReason"
    if reason not in KNOWN_ERROR_CODES:
        return Status.FAIL, f"invalidReason {reason!r} not in the CORE §9 registry"
    return Status.PASS, f"reason {reason!r} is a known code"


def _settle(
    ctx: FacilitatorContext, payload: dict[str, Any], requirements: dict[str, Any]
) -> tuple[SettlementResponse | None, str | None]:
    """Submit one payment payload to settle and classify its strict response."""
    req = {"x402Version": 2, "paymentPayload": payload, "paymentRequirements": requirements}
    try:
        resp = ctx.client.post(
            f"{ctx.base_url.rstrip('/')}/settle", json=req, follow_redirects=False
        )
    except httpx.HTTPError:
        raise
    if not 200 <= resp.status_code < 500:
        return None, f"/settle returned HTTP {resp.status_code}"
    try:
        data: Any = json.loads(resp.text)
        return SettlementResponse.model_validate(data), None
    except (ValueError, ValidationError) as exc:
        return None, f"/settle returned an invalid response: {exc}"


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
        """Construct a facilitator settlement CheckResult with shared catalog metadata."""
        title, sev, ref = ids[cid]
        return CheckResult(cid, title, sev, ref, status, detail)

    if not ctx.allow_settle:
        return [
            mk(c, Status.SKIP, "pass --settle to run /settle tests (moves real funds)") for c in ids
        ]
    if ctx.requirements is None or ctx.signer is None:
        return [mk(c, Status.SKIP, "no --resource requirements / signer") for c in ids]

    results: list[CheckResult] = []

    # FA-SET-001 — valid settle (a real on-chain settlement)
    good = _build_payload(ctx, ctx.requirements)
    r1, r1_error = _settle(ctx, good, ctx.requirements)
    if r1 is None:
        results.append(
            mk("FA-SET-001", Status.FAIL, r1_error or "/settle did not return a valid response")
        )
    elif not r1.success:
        results.append(
            mk(
                "FA-SET-001",
                Status.FAIL,
                f"valid /settle failed: {r1.error_reason!r}",
            )
        )
    elif r1.network != ctx.requirements.get("network"):
        results.append(
            mk("FA-SET-001", Status.FAIL, "settlement network does not match requirement")
        )
    elif not ctx.rpc_url:
        results.append(
            mk(
                "FA-SET-001",
                Status.SKIP,
                "settlement response received but no RPC proof is available",
            )
        )
    else:
        from .payment import _verify_tx_onchain

        proof_status, proof_detail = _verify_tx_onchain(
            ctx.rpc_url,
            r1.transaction,
            asset=str(ctx.requirements["asset"]),
            payer=ctx.signer.address,
            pay_to=str(ctx.requirements["payTo"]),
            amount=int(ctx.requirements["amount"]),
        )
        results.append(mk("FA-SET-001", proof_status, proof_detail))

    # FA-SET-003 — double-settle the SAME payment must be rejected
    if r1 and r1.success:
        r3, r3_error = _settle(ctx, good, ctx.requirements)
        if r3 is None:
            results.append(
                mk(
                    "FA-SET-003",
                    Status.FAIL,
                    r3_error or "second /settle did not return a valid response",
                )
            )
        elif r3.success:
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
                    f"double-settle rejected (reason {r3.error_reason!r})",
                )
            )
    else:
        results.append(mk("FA-SET-003", Status.SKIP, "first settle did not succeed"))

    # FA-SET-002 — invalid settle (value != requirements) must fail with empty tx
    cheap = _build_payload(ctx, {**ctx.requirements, "amount": "1"})
    r2, r2_error = _settle(ctx, cheap, ctx.requirements)
    if r2 is None:
        results.append(
            mk("FA-SET-002", Status.FAIL, r2_error or "/settle did not return a valid response")
        )
    elif r2.success:
        results.append(mk("FA-SET-002", Status.FAIL, "/settle succeeded for an invalid payment"))
    elif r2.transaction:
        results.append(
            mk("FA-SET-002", Status.FAIL, "failed settle still carries a non-empty tx hash")
        )
    else:
        results.append(
            mk("FA-SET-002", Status.PASS, f"correctly failed (reason {r2.error_reason!r})")
        )

    return results


def evaluate_facilitator(ctx: FacilitatorContext | None) -> list[CheckResult]:
    """Run supported, verify, and optional testnet settlement checks for a facilitator."""
    results: list[CheckResult] = []
    for check in FA_REGISTRY:
        if ctx is None:
            status, detail = Status.SKIP, "facilitator unreachable"
        else:
            try:
                status, detail = check.func(ctx)
            except httpx.HTTPError:
                raise
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
    rpc_url: str | None = None,
    timeout: float = 30.0,
    transport: httpx.BaseTransport | None = None,
) -> list[CheckResult]:
    """Probe a facilitator. If resource_url is given, also exercise /verify;
    with allow_settle, also run the FA-SET /settle tests (moves real funds)."""
    headers = {"User-Agent": USER_AGENT}
    with httpx.Client(
        timeout=timeout, transport=transport, headers=headers, follow_redirects=False
    ) as client:
        requirements = None
        extensions: dict[str, Any] = {}
        if resource_url is not None:
            from ..active import choose_eip3009_requirement

            probe = build_probe(client.request("GET", resource_url, follow_redirects=False))
            requirements = choose_eip3009_requirement(probe.raw)
            extensions_raw = probe.raw.get("extensions") if probe.raw is not None else None
            extensions = extensions_raw if isinstance(extensions_raw, dict) else {}
            if allow_settle and requirements is not None:
                DEFAULT_SAFETY_POLICY.require_matching_rpc(requirements.get("network"), rpc_url)
        ctx = FacilitatorContext(
            base_url=base_url,
            client=client,
            requirements=requirements,
            signer=signer,
            resource_url=resource_url,
            extensions=extensions,
            rpc_url=rpc_url,
            allow_settle=allow_settle,
        )
        return evaluate_facilitator(ctx) + evaluate_settle(ctx)
