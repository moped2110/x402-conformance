"""RS-PAY: the positive settlement path (catalog §3).

Sends ONE valid, funded payment and verifies the endpoint delivers the resource,
reports a real settlement, and (optionally, with an RPC URL) that the tx is
actually on-chain. Unlike RS-NEG, this MOVES REAL FUNDS — it runs only behind
the explicit ``--pay`` flag and needs a funded signer.

All assertions share a SINGLE settlement (one nonce, one on-chain tx) so the
group does not spend funds per-check. On-chain verification (RS-PAY-004) lazily
imports web3 and SKIPs if web3 or an RPC URL is absent — the core suite stays
chain-free; on-chain checking is opt-in.
"""

from __future__ import annotations

import concurrent.futures
from typing import Any, cast

from ..active import ActiveContext
from ..models import SettlementResponse
from .base import CheckResult, Severity, Status

_CORE = "x402-specification-v2.md"


def _result(cid: str, title: str, sev: Severity, status: Status, detail: str = "") -> CheckResult:
    return CheckResult(cid, title, sev, f"{_CORE} §6.1.3", status, detail)


def _verify_tx_onchain(rpc_url: str, tx_hash: str) -> tuple[Status, str]:
    try:
        from web3 import Web3
    except Exception:
        return Status.SKIP, "web3 not installed (pip install x402-conformance[onchain])"
    try:
        w3 = Web3(Web3.HTTPProvider(rpc_url))
        receipt = w3.eth.get_transaction_receipt(cast(Any, tx_hash))
    except Exception as exc:
        return Status.FAIL, f"tx {tx_hash} not found on-chain: {exc}"
    if receipt["status"] == 1:
        return Status.PASS, f"tx mined, status 1 (block {receipt['blockNumber']})"
    return Status.FAIL, f"tx {tx_hash} reverted (status {receipt['status']})"


def evaluate_payment(
    context: ActiveContext | None, rpc_url: str | None = None
) -> list[CheckResult]:
    sev_c, sev_m = Severity.CRITICAL, Severity.MAJOR
    titles = {
        "RS-PAY-001": "Valid funded payment is accepted and the resource delivered",
        "RS-PAY-002": "Success carries a valid PAYMENT-RESPONSE settlement",
        "RS-PAY-003": "Settlement network and payer match the payment",
        "RS-PAY-004": "Settlement transaction exists on-chain (status 1)",
        "RS-SEC-001": "Replaying a settled payment is rejected (nonce reuse)",
        "RS-SEC-002": "Concurrent settle of one payment yields at most one success (race)",
    }
    if context is None:
        return [
            _result(
                cid,
                titles[cid],
                sev_m if cid == "RS-PAY-004" else sev_c,
                Status.SKIP,
                "no exact/eip3009 requirement / signer to pay",
            )
            for cid in titles
        ]

    from ..payload_builder import build_exact_eip3009_payload

    payload = build_exact_eip3009_payload(context.requirements, context.signer)
    resp = context.send(payload)
    results: list[CheckResult] = []

    # RS-PAY-001 — resource delivered
    if resp.served_resource:
        results.append(
            _result(
                "RS-PAY-001", titles["RS-PAY-001"], sev_c, Status.PASS, f"status {resp.status_code}"
            )
        )
    else:
        detail = f"status {resp.status_code}"
        if resp.settlement and resp.settlement.error_reason:
            detail += f", reason {resp.settlement.error_reason!r}"
        results.append(
            _result(
                "RS-PAY-001",
                titles["RS-PAY-001"],
                sev_c,
                Status.FAIL,
                f"valid payment was not accepted ({detail})",
            )
        )

    # RS-PAY-002 — settlement response
    settlement: SettlementResponse | None = resp.settlement
    if resp.settlement_error:
        results.append(
            _result("RS-PAY-002", titles["RS-PAY-002"], sev_c, Status.FAIL, resp.settlement_error)
        )
    elif settlement is None:
        results.append(
            _result(
                "RS-PAY-002",
                titles["RS-PAY-002"],
                sev_c,
                Status.FAIL,
                "no PAYMENT-RESPONSE header on a successful payment",
            )
        )
    elif not settlement.success:
        results.append(
            _result(
                "RS-PAY-002",
                titles["RS-PAY-002"],
                sev_c,
                Status.FAIL,
                f"settlement.success is false (reason {settlement.error_reason!r})",
            )
        )
    elif not settlement.transaction or settlement.transaction == "0x":
        results.append(
            _result(
                "RS-PAY-002",
                titles["RS-PAY-002"],
                sev_c,
                Status.FAIL,
                "settlement.success but transaction hash is empty",
            )
        )
    else:
        results.append(
            _result(
                "RS-PAY-002",
                titles["RS-PAY-002"],
                sev_c,
                Status.PASS,
                f"tx {settlement.transaction}",
            )
        )

    # RS-PAY-003 — network + payer consistency
    if settlement is None or not settlement.success:
        results.append(
            _result(
                "RS-PAY-003",
                titles["RS-PAY-003"],
                sev_m,
                Status.SKIP,
                "no successful settlement to inspect",
            )
        )
    else:
        problems = []
        if settlement.network != context.requirements.get("network"):
            problems.append(
                f"network {settlement.network!r} != {context.requirements.get('network')!r}"
            )
        payer = getattr(settlement, "payer", None)
        if payer and payer.lower() != context.signer.address.lower():
            problems.append(f"payer {payer!r} != signer {context.signer.address!r}")
        if problems:
            results.append(
                _result("RS-PAY-003", titles["RS-PAY-003"], sev_m, Status.FAIL, "; ".join(problems))
            )
        else:
            results.append(_result("RS-PAY-003", titles["RS-PAY-003"], sev_m, Status.PASS, ""))

    # RS-PAY-004 — on-chain verification (opt-in)
    tx = settlement.transaction if (settlement and settlement.success) else ""
    if not tx or tx == "0x":
        results.append(
            _result(
                "RS-PAY-004", titles["RS-PAY-004"], sev_m, Status.SKIP, "no settlement tx to verify"
            )
        )
    elif not rpc_url:
        results.append(
            _result(
                "RS-PAY-004",
                titles["RS-PAY-004"],
                sev_m,
                Status.SKIP,
                "no --rpc-url given; pass one to verify the tx on-chain",
            )
        )
    else:
        status, detail = _verify_tx_onchain(rpc_url, tx)
        results.append(_result("RS-PAY-004", titles["RS-PAY-004"], sev_m, status, detail))

    # RS-SEC-001 — replay the just-settled payment (same nonce) must be rejected.
    if settlement is not None and settlement.success:
        replay = context.send(payload)  # identical PAYMENT-SIGNATURE / nonce
        if replay.served_resource or replay.settled_ok:
            results.append(
                _result(
                    "RS-SEC-001",
                    titles["RS-SEC-001"],
                    sev_c,
                    Status.FAIL,
                    f"replay of a settled payment was accepted "
                    f"(status {replay.status_code}) — nonce reuse not prevented",
                )
            )
        else:
            results.append(
                _result(
                    "RS-SEC-001",
                    titles["RS-SEC-001"],
                    sev_c,
                    Status.PASS,
                    f"replay correctly rejected (status {replay.status_code})",
                )
            )
    else:
        results.append(
            _result(
                "RS-SEC-001",
                titles["RS-SEC-001"],
                sev_c,
                Status.SKIP,
                "no successful settlement to replay",
            )
        )

    # RS-SEC-002 — fire N identical payments concurrently; at most one may settle.
    if settlement is not None and settlement.success:
        race = build_exact_eip3009_payload(context.requirements, context.signer)
        n = 5
        with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex:
            responses = list(ex.map(lambda _: context.send(race), range(n)))
        settled = sum(1 for r in responses if r.served_resource or r.settled_ok)
        if settled >= 2:
            results.append(
                _result(
                    "RS-SEC-002",
                    titles["RS-SEC-002"],
                    sev_c,
                    Status.FAIL,
                    f"{settled}/{n} concurrent settles of one payment succeeded "
                    f"— nonce reuse under concurrency (double-settle)",
                )
            )
        else:
            results.append(
                _result(
                    "RS-SEC-002",
                    titles["RS-SEC-002"],
                    sev_c,
                    Status.PASS,
                    f"{settled}/{n} concurrent settles succeeded (no double-settle)",
                )
            )
    else:
        results.append(
            _result(
                "RS-SEC-002",
                titles["RS-SEC-002"],
                sev_c,
                Status.SKIP,
                "no successful settlement to race",
            )
        )

    return results
