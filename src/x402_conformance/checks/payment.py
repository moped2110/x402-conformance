"""RS-PAY: the positive settlement path (catalog §3).

Sends ONE valid, funded payment and verifies the endpoint delivers the resource,
reports a real settlement, and (optionally, with an RPC URL) that the tx is
actually on-chain. Unlike RS-NEG, this MOVES REAL FUNDS — it runs only behind
the explicit ``--pay`` flag and needs a funded signer.

All assertions share a SINGLE settlement (one nonce, one on-chain tx) so the
group does not spend funds per-check. The pay path requires a matching testnet/
local RPC and lazily imports web3 for fail-closed balance and receipt checks;
the passive core stays chain-free.
"""

from __future__ import annotations

import concurrent.futures
import re
from typing import Any, cast

from ..active import ActiveContext, ActiveResponse
from ..models import SettlementResponse
from .base import CheckResult, Severity, Status

_CORE = "x402-specification-v2.md"

#: Every check id this group can emit. Used by the caller's group-level safety net
#: (run_payment_checks) to report ERROR for all of them if the linear pay flow crashes.
PAY_CHECK_IDS = [
    "RS-PAY-001",
    "RS-PAY-002",
    "RS-PAY-003",
    "RS-PAY-004",
    "RS-SEC-001",
    "RS-SEC-002",
    "RS-HS-008",
]


def _result(cid: str, title: str, sev: Severity, status: Status, detail: str = "") -> CheckResult:
    """Construct a payment-flow CheckResult with the correct shared severity and reference."""
    return CheckResult(cid, title, sev, f"{_CORE} §6.1.3", status, detail)


def _pay_severity(check_id: str) -> Severity:
    """Severity for one payment-group check.

    The group is CRITICAL by default because it decides whether money moved.
    RS-PAY-004 is MAJOR (proof depth, not acceptance) and RS-HS-008 is MINOR —
    a cacheable paid response is a real leak, but it is a header-hygiene finding
    and must not gate a settlement verdict.
    """
    if check_id == "RS-PAY-004":
        return Severity.MAJOR
    if check_id == "RS-HS-008":
        return Severity.MINOR
    return Severity.CRITICAL


def _evaluate_paid_cacheability(resp: ActiveResponse, title: str) -> CheckResult:
    """Grade RS-HS-008: the paid 200 must not be storable by a shared cache."""
    cid = "RS-HS-008"
    if not resp.served_resource:
        return _result(cid, title, Severity.MINOR, Status.SKIP, "no paid response to inspect")
    cache_control = resp.headers.get("cache-control", "").lower()
    if not cache_control:
        # A 200 with no Cache-Control IS heuristically cacheable (RFC 9111 §4.2.2),
        # unlike a 402. For a response the client just paid for that is a real gap,
        # but it is advisory: the endpoint may front no shared cache at all.
        return _result(
            cid,
            title,
            Severity.MINOR,
            Status.PASS,
            "paid 200 carries no Cache-Control; explicit 'private' recommended "
            "(a shared cache may store and reserve it to an unpaid client)",
        )
    if "no-store" in cache_control or "private" in cache_control:
        return _result(cid, title, Severity.MINOR, Status.PASS, "")
    if "public" in cache_control or _positive_max_age(cache_control):
        return _result(
            cid,
            title,
            Severity.MINOR,
            Status.FAIL,
            f"paid 200 is shared-cacheable (Cache-Control: {cache_control!r}) — a CDN "
            "or proxy can serve the resource this client paid for to clients who did not",
        )
    return _result(cid, title, Severity.MINOR, Status.PASS, "")


def _positive_max_age(cache_control: str) -> bool:
    """Detect a positive max-age or s-maxage directive in Cache-Control."""
    for part in cache_control.split(","):
        part = part.strip()
        if part.startswith("max-age=") or part.startswith("s-maxage="):
            value = part.split("=", 1)[1].strip()
            if value.isdigit() and int(value) > 0:
                return True
    return False


#: ERC-20 balanceOf(address) selector.
_SEL_BALANCE_OF = "70a08231"
_EVM_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_EVM_TX_HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
_TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


def _read_token_balance(rpc_url: str, token: str, owner: str) -> int | None:
    """Read ``owner``'s ERC-20 balance of ``token`` via a read-only ``eth_call``.

    Returns None when the balance can't be read (web3 missing, bad address, RPC
    error). The caller fails closed and sends no payment in that case.
    READ-ONLY: never signs or sends (money invariant)."""
    try:
        from web3 import Web3
    except Exception:
        return None
    try:
        w3 = Web3(Web3.HTTPProvider(rpc_url))
        data = "0x" + _SEL_BALANCE_OF + owner.lower().removeprefix("0x").rjust(64, "0")
        raw = w3.eth.call(cast(Any, {"to": Web3.to_checksum_address(token), "data": data}))
        return int(raw.hex(), 16) if raw else 0
    except Exception:
        return None


def _hex(value: object) -> str:
    """Normalize bytes, integers, or hex-like values into lowercase prefixed hex."""
    if isinstance(value, bytes):
        return "0x" + value.hex()
    raw = value.hex() if hasattr(value, "hex") else str(value)
    text = str(raw)
    return text if text.startswith("0x") else "0x" + text


def _address_topic(address: str) -> str:
    """Encode an EVM address as the zero-padded topic representation."""
    return "0x" + address.removeprefix("0x").lower().rjust(64, "0")


def _verify_transfer_logs(
    receipt: Any, *, asset: str, payer: str, pay_to: str, amount: int
) -> tuple[Status, str]:
    """Prove the receipt contains one unambiguous expected ERC-20 Transfer."""

    if not all(_EVM_ADDRESS_RE.fullmatch(a) for a in (asset, payer, pay_to)):
        return Status.FAIL, "cannot verify transfer: malformed asset/payer/payTo address"
    transfer_logs: list[Any] = []
    for log in receipt.get("logs", []):
        try:
            if str(log["address"]).lower() != asset.lower():
                continue
            topics = log["topics"]
            if topics and _hex(topics[0]).lower() == _TRANSFER_TOPIC:
                transfer_logs.append(log)
        except (KeyError, TypeError):
            continue
    if len(transfer_logs) != 1:
        return (
            Status.FAIL,
            f"expected exactly one Transfer from asset {asset}, found {len(transfer_logs)} "
            "(missing transfer or multiple-transfer/fee-on-transfer ambiguity)",
        )
    log = transfer_logs[0]
    try:
        topics = log["topics"]
        if len(topics) != 3:
            return Status.FAIL, f"Transfer log has {len(topics)} topics, expected 3"
        actual_from = _hex(topics[1]).lower()
        actual_to = _hex(topics[2]).lower()
        actual_amount = int(_hex(log["data"]), 16)
    except (KeyError, TypeError, ValueError) as exc:
        return Status.FAIL, f"malformed Transfer log: {type(exc).__name__}"
    problems: list[str] = []
    if actual_from != _address_topic(payer):
        problems.append("payer/from does not match signer")
    if actual_to != _address_topic(pay_to):
        problems.append("recipient/to does not match payTo")
    if actual_amount != amount:
        problems.append(f"amount {actual_amount} != required {amount}")
    if problems:
        return Status.FAIL, "; ".join(problems)
    return Status.PASS, f"Transfer {amount} {asset} from {payer} to {pay_to} proven on-chain"


def _verify_tx_onchain(
    rpc_url: str,
    tx_hash: str,
    *,
    asset: str,
    payer: str,
    pay_to: str,
    amount: int,
) -> tuple[Status, str]:
    """Prove a successful receipt contains exactly the expected token Transfer event."""
    if not _EVM_TX_HASH_RE.fullmatch(tx_hash):
        return Status.FAIL, f"settlement transaction {tx_hash!r} is not a canonical EVM tx hash"
    try:
        from web3 import Web3
    except Exception:
        return Status.SKIP, "web3 not installed (pip install x402-conformance[onchain])"
    try:
        w3 = Web3(Web3.HTTPProvider(rpc_url))
        receipt = w3.eth.get_transaction_receipt(cast(Any, tx_hash))
    except Exception as exc:
        return Status.FAIL, f"tx {tx_hash} not found on-chain: {exc}"
    try:
        receipt_hash = receipt.get("transactionHash")
        if receipt_hash is not None and _hex(receipt_hash).lower() != tx_hash.lower():
            return Status.FAIL, "RPC receipt transactionHash does not match settlement response"
        if int(receipt["status"]) != 1:
            return Status.FAIL, f"tx {tx_hash} reverted (status {receipt['status']})"
    except (KeyError, TypeError, ValueError) as exc:
        return Status.FAIL, f"malformed transaction receipt: {type(exc).__name__}"
    status, detail = _verify_transfer_logs(
        receipt, asset=asset, payer=payer, pay_to=pay_to, amount=amount
    )
    if status == Status.PASS:
        detail += f" (block {receipt.get('blockNumber', '?')})"
    return status, detail


def evaluate_payment(
    context: ActiveContext | None, rpc_url: str | None = None
) -> list[CheckResult]:
    """Run positive payment, settlement-header, on-chain proof, and replay checks in order."""
    sev_c, sev_m = Severity.CRITICAL, Severity.MAJOR
    titles = {
        "RS-PAY-001": "Valid funded payment is accepted and the resource delivered",
        "RS-PAY-002": "Success carries a valid PAYMENT-RESPONSE settlement",
        "RS-PAY-003": "Settlement network and payer match the payment",
        "RS-PAY-004": "Settlement transaction proves the expected on-chain transfer",
        "RS-SEC-001": "Replaying a settled payment is rejected (nonce reuse)",
        "RS-SEC-002": "Concurrent settle of one payment yields at most one success (race)",
        "RS-HS-008": "Paid 200 response is not shared-cacheable",
    }
    if context is None:
        return [
            _result(
                cid,
                titles[cid],
                _pay_severity(cid),
                Status.SKIP,
                "no exact/eip3009 requirement / signer to pay",
            )
            for cid in titles
        ]

    # Balance precheck (opt-in, needs --rpc-url): a valid payment from an underfunded
    # signer can't settle. Rather than move toward a doomed on-chain attempt, read the
    # signer's token balance first and SKIP the whole group with a clear reason. This
    # only READS the chain (money invariant) and never blocks on a flaky read.
    try:
        needed = int(context.requirements.get("amount", 0))
    except (TypeError, ValueError):
        needed = 0
    if rpc_url and needed <= 0:
        detail = "invalid required amount; RPC payment preflight failed closed (no payment sent)"
        return [
            _result(
                cid,
                titles[cid],
                _pay_severity(cid),
                Status.ERROR,
                detail,
            )
            for cid in titles
        ]
    if rpc_url:
        balance = _read_token_balance(
            rpc_url, str(context.requirements.get("asset", "")), context.signer.address
        )
        if balance is None:
            detail = (
                "unable to read signer token balance; RPC preflight failed closed (no payment sent)"
            )
            return [
                _result(
                    cid,
                    titles[cid],
                    _pay_severity(cid),
                    Status.ERROR,
                    detail,
                )
                for cid in titles
            ]
        if balance < needed:
            detail = f"insufficient signer balance: have {balance}, need {needed} (no payment sent)"
            return [
                _result(
                    cid,
                    titles[cid],
                    _pay_severity(cid),
                    Status.SKIP,
                    detail,
                )
                for cid in titles
            ]

    from ..payload_builder import build_exact_eip3009_payload

    payload = build_exact_eip3009_payload(
        context.requirements,
        context.signer,
        resource_url=context.resource_url,
        extensions=context.extensions,
    )
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

    # RS-HS-008 — the *paid* response must not be shared-cacheable.
    # RS-HS-007 covers the 402. This covers the 200 that carries the content the
    # client just paid for: a shared cache storing it serves the paid resource to
    # the next unpaid client. Upstream made `private` the default on the settled
    # response in x402#2990 (TS/Python) alongside no-store on the 402.
    results.append(_evaluate_paid_cacheability(resp, titles["RS-HS-008"]))

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
        payer = settlement.payer
        if not payer:
            problems.append("settlement response does not identify payer")
        elif payer.lower() != context.signer.address.lower():
            problems.append(f"payer {payer!r} != signer {context.signer.address!r}")
        if settlement.amount is not None and settlement.amount != str(
            context.requirements.get("amount")
        ):
            problems.append(
                f"amount {settlement.amount!r} != {context.requirements.get('amount')!r}"
            )
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
        status, detail = _verify_tx_onchain(
            rpc_url,
            tx,
            asset=str(context.requirements.get("asset", "")),
            payer=context.signer.address,
            pay_to=str(context.requirements.get("payTo", "")),
            amount=needed,
        )
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
        race = build_exact_eip3009_payload(
            context.requirements,
            context.signer,
            resource_url=context.resource_url,
            extensions=context.extensions,
        )
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
