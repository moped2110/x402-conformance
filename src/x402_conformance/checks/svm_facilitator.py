"""FA-SVM: live ``/verify`` conformance for the exact-SVM scheme (SOLANA-PLAN §5).

Black-box, standalone check group. It builds a valid client-signed ``exact``-SVM
payment plus one structurally tampered variant per spec MUST, POSTs each to a
facilitator's ``POST /verify``, and asserts the facilitator **accepts** the valid
payment and **rejects** every tampered one. A facilitator that returns
``isValid:true`` for a tampered payload — or answers with anything other than a
clean ``isValid:false`` — is flagged. That is exactly the gap in *thin* facilitators
that delegate to a signer (e.g. Kora's ``signTransaction``) and return ``isValid:true``
whenever signing succeeds, without structurally verifying the x402 payload. The
Kora x402 demo facilitator is such a thin verifier; this group makes that visible.

Deliberately ``/verify`` only: it never calls ``/settle``, so no funds move and no
fees are spent beyond the payer's own signature over the message. This keeps the
probe aligned with the money-invariant (a test tool must never move real value).

Not part of the passive REGISTRY or the FA_REGISTRY, and not wired into the default
run or the conformance catalog: it needs a live SVM facilitator plus the ``[svm]``
extra (``solders``) and a funded payer, so it is invoked explicitly
(``run_svm_facilitator_checks`` / ``python -m x402_conformance.checks.svm_facilitator``).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx
from pydantic import ValidationError

from .. import USER_AGENT
from ..models import VerifyResponse
from ..svm import TOKEN_PROGRAM, SvmTamper, build_exact_svm_transaction
from .base import CheckResult, Severity, Status
from .facilitator import KNOWN_ERROR_CODES

_SPEC = "specs/schemes/exact/scheme_exact_svm.md"

#: HTTP statuses that mean ``/verify`` is not implemented (not a conformance verdict).
#: Mirrors ``facilitator._ENDPOINT_ABSENT`` — kept local to avoid a private cross-import.
_ENDPOINT_ABSENT = frozenset({404, 405, 501})


def _absence_reason(path: str, status: int) -> str:
    """Explain that a facilitator endpoint is missing rather than misbehaving."""
    return f"{path} is not implemented (HTTP {status}) — no facilitator behaviour to test."


# A valid, well-known non-merchant owner: the System Program's address is a real
# 32-byte pubkey but is never the payTo, so a transfer to *its* ATA is a clean
# "wrong recipient" that a conformant facilitator must reject (incorrect-ATA MUST).
_DECOY_PAYEE = "11111111111111111111111111111111"


@dataclass
class SvmFacilitatorContext:
    """Everything the FA-SVM cases need to build payloads and reach a facilitator.

    ``recent_blockhash`` is a base58 blockhash the payloads reference; for a live run
    it comes from ``getLatestBlockhash`` (see ``run_svm_facilitator_checks``), for an
    offline test any fixed value works because ``/verify`` is mocked.
    """

    base_url: str
    client: httpx.Client
    network: str
    asset: str  # SPL mint
    decimals: int
    pay_to: str
    amount: int
    fee_payer: str
    payer_keypair_bytes: bytes
    recent_blockhash: str
    resource_url: str = "http://localhost:4021/protected"
    token_program: str = TOKEN_PROGRAM
    max_timeout_seconds: int = 300


def _requirements(ctx: SvmFacilitatorContext) -> dict[str, Any]:
    """The x402 v2 paymentRequirements the facilitator verifies the payload against."""
    return {
        "scheme": "exact",
        "network": ctx.network,
        "amount": str(ctx.amount),
        "asset": ctx.asset,
        "payTo": ctx.pay_to,
        "maxTimeoutSeconds": ctx.max_timeout_seconds,
        "extra": {"feePayer": ctx.fee_payer},
    }


def _verify_request(
    ctx: SvmFacilitatorContext, b64_tx: str, requirements: dict[str, Any]
) -> dict[str, Any]:
    """Assemble a ``/verify`` request body in the exact shape a real x402 SVM client
    sends (captured from the Kora x402 demo): the transaction plus the accepted
    requirements, wrapped in ``paymentPayload`` and mirrored in ``paymentRequirements``."""
    return {
        "x402Version": 2,
        "paymentPayload": {
            "x402Version": 2,
            "payload": {"transaction": b64_tx},
            "resource": {
                "url": ctx.resource_url,
                "description": "Protected endpoint",
                "mimeType": "application/json",
            },
            "accepted": requirements,
        },
        "paymentRequirements": requirements,
    }


def _verify(
    ctx: SvmFacilitatorContext, b64_tx: str, requirements: dict[str, Any]
) -> tuple[VerifyResponse | None, str | None, int | None]:
    """POST one SVM payload to ``/verify`` and strictly parse the response.

    Returns ``(response, error, status_code)``; a status in ``_ENDPOINT_ABSENT``
    means there is no ``/verify`` there and must not be graded as a conformance fault.
    """
    req = _verify_request(ctx, b64_tx, requirements)
    resp = ctx.client.post(f"{ctx.base_url.rstrip('/')}/verify", json=req, follow_redirects=False)
    if resp.status_code in _ENDPOINT_ABSENT:
        return None, _absence_reason("/verify", resp.status_code), resp.status_code
    if not 200 <= resp.status_code < 500:
        return None, f"/verify returned HTTP {resp.status_code}", resp.status_code
    try:
        data: Any = json.loads(resp.text)
        return VerifyResponse.model_validate(data), None, resp.status_code
    except (ValueError, ValidationError) as exc:
        return None, f"/verify returned an invalid response: {exc}", resp.status_code


def _build(
    ctx: SvmFacilitatorContext,
    *,
    amount: int | None = None,
    pay_to: str | None = None,
    tamper: SvmTamper | None = None,
) -> str:
    """Build one exact-SVM payload from the context, optionally under-paying, paying a
    decoy recipient, or applying a structural tamper."""
    return build_exact_svm_transaction(
        payer_keypair_bytes=ctx.payer_keypair_bytes,
        fee_payer=ctx.fee_payer,
        mint=ctx.asset,
        decimals=ctx.decimals,
        pay_to=ctx.pay_to if pay_to is None else pay_to,
        amount=ctx.amount if amount is None else amount,
        recent_blockhash=ctx.recent_blockhash,
        # Memo-free 3-instruction baseline: matches the x402 reference client exactly and
        # stays portable to facilitators (like the Kora demo) that do not allowlist Memo,
        # so a rejection reflects the tamper — not an unrelated program-allowlist policy.
        include_memo=False,
        token_program=ctx.token_program,
        tamper=tamper,
    )


@dataclass(frozen=True)
class _SvmCase:
    """One FA-SVM case: its catalog identity, how to build its payload, and whether a
    conformant facilitator must find it valid."""

    check_id: str
    title: str
    severity: Severity
    spec_ref: str
    make: Callable[[SvmFacilitatorContext], str]
    expect_valid: bool


CASES: list[_SvmCase] = [
    _SvmCase(
        "FA-SVM-VER-001",
        "A valid exact-SVM payment is accepted (isValid:true)",
        Severity.CRITICAL,
        f"{_SPEC} §1–2",
        lambda ctx: _build(ctx),
        expect_valid=True,
    ),
    _SvmCase(
        "FA-SVM-VER-002",
        "A payload outside the 3–7 instruction Path-1 layout is rejected",
        Severity.MAJOR,
        f"{_SPEC} §1 (instructions_length)",
        lambda ctx: _build(ctx, tamper=SvmTamper.DROP_COMPUTE_BUDGET),
        expect_valid=False,
    ),
    _SvmCase(
        "FA-SVM-VER-003",
        "A non-TransferChecked token instruction is rejected",
        Severity.CRITICAL,
        f"{_SPEC} §1.2 (not_spl_token_transfer_checked)",
        lambda ctx: _build(ctx, tamper=SvmTamper.NOT_TRANSFER_CHECKED),
        expect_valid=False,
    ),
    _SvmCase(
        "FA-SVM-VER-004",
        "A second matching transfer (double-settle) is rejected",
        Severity.CRITICAL,
        f"{_SPEC} §1.4 (exactly-one transfer)",
        lambda ctx: _build(ctx, tamper=SvmTamper.DOUBLE_TRANSFER),
        expect_valid=False,
    ),
    _SvmCase(
        "FA-SVM-VER-005",
        "The feePayer wired into the transfer accounts is rejected",
        Severity.CRITICAL,
        f"{_SPEC} §2.1.1 (fee_payer_included_in_instruction_accounts)",
        lambda ctx: _build(ctx, tamper=SvmTamper.FEE_PAYER_IN_ACCOUNTS),
        expect_valid=False,
    ),
    _SvmCase(
        "FA-SVM-VER-006",
        "An underpaying transfer (amount < required) is rejected",
        Severity.CRITICAL,
        f"{_SPEC} § amount (amount_mismatch)",
        lambda ctx: _build(ctx, amount=1),
        expect_valid=False,
    ),
    _SvmCase(
        "FA-SVM-VER-007",
        "A transfer to an ATA other than payTo's is rejected",
        Severity.CRITICAL,
        f"{_SPEC} §dest-ATA (transfer_to_incorrect_ata)",
        lambda ctx: _build(ctx, pay_to=_DECOY_PAYEE),
        expect_valid=False,
    ),
]


def _grade(case: _SvmCase, resp: VerifyResponse | None, error: str | None) -> tuple[Status, str]:
    """Turn one ``/verify`` outcome into a PASS/FAIL for the case's expectation."""
    if resp is None:
        # Not a clean VerifyResponse. For the valid case that is a plain failure; for a
        # tampered case a conformant facilitator still owes a clean isValid:false, so an
        # unparseable/5xx answer is a fault too (it did not properly reject).
        return Status.FAIL, error or "/verify did not return a valid response"
    if case.expect_valid:
        if resp.is_valid:
            return Status.PASS, "valid payment accepted"
        return Status.FAIL, f"valid payment rejected as {resp.invalid_reason!r}"
    # Negative case: the facilitator MUST report isValid:false.
    if resp.is_valid:
        return Status.FAIL, (
            "facilitator accepted a structurally tampered payload — it does not verify "
            "the x402 structure (thin verifier: signs/relays without checking)"
        )
    reason = resp.invalid_reason
    note = "" if reason in KNOWN_ERROR_CODES else f" (reason {reason!r} not in CORE §9 registry)"
    return Status.PASS, f"correctly rejected as {reason!r}{note}"


def evaluate_svm_facilitator(ctx: SvmFacilitatorContext | None) -> list[CheckResult]:
    """Run every FA-SVM case against ``/verify``. With no context, all cases SKIP."""
    results: list[CheckResult] = []
    for case in CASES:
        if ctx is None:
            status, detail = Status.SKIP, "no SVM facilitator context (needs a live facilitator)"
        else:
            try:
                payload = case.make(ctx)
                requirements = _requirements(ctx)
                resp, error, http_status = _verify(ctx, payload, requirements)
                if http_status in _ENDPOINT_ABSENT:
                    status = Status.SKIP
                    detail = error or _absence_reason("/verify", http_status or 404)
                else:
                    status, detail = _grade(case, resp, error)
            except httpx.HTTPError as exc:
                status, detail = Status.SKIP, f"/verify unreachable: {exc}"
            except Exception as exc:  # a bug in this suite, not the facilitator
                status, detail = Status.ERROR, f"check crashed (suite bug): {exc!r}"
        results.append(
            CheckResult(case.check_id, case.title, case.severity, case.spec_ref, status, detail)
        )
    return results


def _load_payer_keypair_bytes(source: str) -> bytes:
    """Load a 64-byte Solana keypair from a JSON keypair file path or a base58 secret.

    Accepts either a path to a ``solana-keygen`` JSON array file or a raw base58
    secret string (the form stored in the demo ``.env``). Needs the ``[svm]`` extra.
    """
    import os

    from solders.keypair import Keypair

    if os.path.isfile(source):
        with open(source, encoding="utf-8") as fh:
            data = json.load(fh)
        from_json: bytes = bytes(Keypair.from_bytes(bytes(data)))
        return from_json
    from_b58: bytes = bytes(Keypair.from_base58_string(source))
    return from_b58


def _fetch_recent_blockhash(
    client: httpx.Client, rpc_url: str
) -> str:  # pragma: no cover - live RPC
    """Fetch a fresh base58 blockhash from a Solana RPC (``getLatestBlockhash``)."""
    resp = client.post(
        rpc_url,
        json={"jsonrpc": "2.0", "id": 1, "method": "getLatestBlockhash", "params": []},
    )
    resp.raise_for_status()
    value: str = resp.json()["result"]["value"]["blockhash"]
    return value


def run_svm_facilitator_checks(  # pragma: no cover - live facilitator entry
    *,
    base_url: str,
    network: str,
    asset: str,
    decimals: int,
    pay_to: str,
    amount: int,
    fee_payer: str,
    payer: str,
    rpc_url: str | None = None,
    recent_blockhash: str | None = None,
    resource_url: str = "http://localhost:4021/protected",
    token_program: str = TOKEN_PROGRAM,
    timeout: float = 30.0,
    transport: httpx.BaseTransport | None = None,
) -> list[CheckResult]:
    """Probe a live SVM facilitator's ``/verify`` with the FA-SVM matrix.

    Supply either ``recent_blockhash`` directly or an ``rpc_url`` to fetch one. Never
    calls ``/settle`` — no funds move.
    """
    headers = {"User-Agent": USER_AGENT}
    with httpx.Client(
        timeout=timeout, transport=transport, headers=headers, follow_redirects=False
    ) as client:
        if recent_blockhash is None:
            if rpc_url is None:
                raise ValueError("pass recent_blockhash or rpc_url")
            recent_blockhash = _fetch_recent_blockhash(client, rpc_url)
        ctx = SvmFacilitatorContext(
            base_url=base_url,
            client=client,
            network=network,
            asset=asset,
            decimals=decimals,
            pay_to=pay_to,
            amount=amount,
            fee_payer=fee_payer,
            payer_keypair_bytes=_load_payer_keypair_bytes(payer),
            recent_blockhash=recent_blockhash,
            resource_url=resource_url,
            token_program=token_program,
        )
        return evaluate_svm_facilitator(ctx)


def _main() -> int:  # pragma: no cover - manual live entry
    """CLI entry: run the FA-SVM matrix against a live facilitator and print results."""
    import argparse

    from ..svm import SOLANA_DEVNET

    parser = argparse.ArgumentParser(
        prog="python -m x402_conformance.checks.svm_facilitator",
        description="FA-SVM: probe a facilitator's /verify with valid + tampered exact-SVM "
        "payloads. /verify only — no funds move.",
    )
    parser.add_argument("--facilitator-url", required=True, help="facilitator base URL")
    parser.add_argument("--payer", required=True, help="payer keypair JSON file path or base58")
    parser.add_argument("--asset", required=True, help="SPL mint address")
    parser.add_argument("--pay-to", required=True, help="merchant payTo address")
    parser.add_argument("--fee-payer", required=True, help="sponsor / feePayer address")
    parser.add_argument("--amount", type=int, default=1000, help="required amount (base units)")
    parser.add_argument("--decimals", type=int, default=6, help="mint decimals")
    parser.add_argument("--network", default=SOLANA_DEVNET, help="CAIP-2 network id")
    parser.add_argument("--rpc-url", default=None, help="RPC to fetch a recent blockhash")
    parser.add_argument("--recent-blockhash", default=None, help="base58 blockhash (skips RPC)")
    args = parser.parse_args()

    results = run_svm_facilitator_checks(
        base_url=args.facilitator_url,
        network=args.network,
        asset=args.asset,
        decimals=args.decimals,
        pay_to=args.pay_to,
        amount=args.amount,
        fee_payer=args.fee_payer,
        payer=args.payer,
        rpc_url=args.rpc_url,
        recent_blockhash=args.recent_blockhash,
    )
    marks = {Status.PASS: "PASS", Status.FAIL: "FAIL", Status.SKIP: "SKIP", Status.ERROR: "ERR "}
    failures = 0
    for r in results:
        print(f"[{marks[r.status]}] {r.check_id}  {r.title}\n        {r.detail}")
        if r.status in (Status.FAIL, Status.ERROR):
            failures += 1
    print(f"\n{failures} failing / {len(results)} checks")
    return 1 if failures else 0


if __name__ == "__main__":  # pragma: no cover - manual live entry
    raise SystemExit(_main())
