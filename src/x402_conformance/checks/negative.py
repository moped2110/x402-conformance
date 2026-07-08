"""RS-NEG: active negative checks (catalog §4) + cross-chain replay (RS-SEC-010).

Each check builds a payment, deliberately breaks exactly one thing, sends it,
and asserts the endpoint *rejects* it. A correct server rejects every one of
these at the verification step — before any on-chain settlement — which is why
the negative group needs no funded payer, only a throwaway signer.

These checks run only in active mode (``--active``). They are NOT part of the
passive REGISTRY; ``evaluate_active`` drives them explicitly.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ..active import ActiveContext, ActiveResponse
from ..payload_builder import (
    build_exact_eip3009_payload,
    make_expired,
    make_not_yet_valid,
    tamper_recipient,
    tamper_signature,
    tamper_value_lower,
)
from .base import CheckResult, Severity, Status

_CORE = "x402-specification-v2.md"
_ATTACKER = "0x000000000000000000000000000000000000dEaD"
_OTHER_ASSET = "0x1111111111111111111111111111111111111111"
# A resource URL deliberately different from the one under test, for the cross-resource
# binding probe (RS-SEC-003). The EIP-3009 authorization does not sign the resource.
_FOREIGN_RESOURCE = "https://cross-resource-probe.example/other"
# A well-known EOA (Anvil dev account #0): definitively has NO contract code on
# any chain, so it can never be a token. Probes the "asset is not a deployed
# contract" bypass class (x402#2554, reason asset_not_deployed_contract).
_EOA_ASSET = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

ActiveFunc = Callable[[ActiveContext], "tuple[Status, str]"]


@dataclass(frozen=True)
class _ActiveCheck:
    check_id: str
    title: str
    severity: Severity
    spec_ref: str
    func: ActiveFunc


ACTIVE_REGISTRY: list[_ActiveCheck] = []


def _register(
    check_id: str, title: str, severity: Severity, spec_ref: str
) -> Callable[[ActiveFunc], ActiveFunc]:
    def deco(func: ActiveFunc) -> ActiveFunc:
        ACTIVE_REGISTRY.append(_ActiveCheck(check_id, title, severity, spec_ref, func))
        return func

    return deco


def _assert_rejected(resp: ActiveResponse) -> tuple[Status, str]:
    """Shared verdict: an invalid payment must not be served or settled."""
    if resp.served_resource:
        return Status.FAIL, (
            f"endpoint returned {resp.status_code} and SERVED the resource for an invalid "
            "payment — revenue/security leak"
        )
    if resp.settled_ok:
        return Status.FAIL, "endpoint reported successful settlement for an invalid payment"
    if resp.marker_leaked:
        return Status.FAIL, (
            f"status {resp.status_code} but the response body contained the resource "
            "marker — protected content leaked on the rejection path (RS-SEC-009)"
        )
    return Status.PASS, f"correctly rejected (status {resp.status_code})"


# --- malformed transport payloads (no signing needed) ---


@_register(
    "RS-NEG-001",
    "Garbage base64 in PAYMENT-SIGNATURE is rejected",
    Severity.MAJOR,
    "transports-v2/http.md §Error Handling",
)
def neg_001(ctx: ActiveContext) -> tuple[Status, str]:
    return _assert_rejected(ctx.send_header("!!!not-base64!!!"))


@_register(
    "RS-NEG-002",
    "Valid base64 but malformed JSON is rejected",
    Severity.MAJOR,
    "transports-v2/http.md §Error Handling",
)
def neg_002(ctx: ActiveContext) -> tuple[Status, str]:
    import base64

    bad = base64.b64encode(b"{not valid json").decode()
    return _assert_rejected(ctx.send_header(bad))


# --- signed-but-invalid payloads ---


@_register(
    "RS-NEG-003", "Tampered signature is rejected", Severity.CRITICAL, f"{_CORE} §6.1.2 step 1"
)
def neg_003(ctx: ActiveContext) -> tuple[Status, str]:
    payload = build_exact_eip3009_payload(ctx.requirements, ctx.signer)
    return _assert_rejected(ctx.send(tamper_signature(payload)))


@_register(
    "RS-NEG-005",
    "Underpayment (authorized value < required) is rejected",
    Severity.CRITICAL,
    f"{_CORE} §6.1.2 step 3",
)
def neg_005(ctx: ActiveContext) -> tuple[Status, str]:
    payload = build_exact_eip3009_payload(ctx.requirements, ctx.signer)
    return _assert_rejected(ctx.send(tamper_value_lower(payload, factor=0.5)))


@_register(
    "RS-NEG-007",
    "Recipient mismatch (payTo redirected) is rejected",
    Severity.CRITICAL,
    f"{_CORE} §9 recipient_mismatch",
)
def neg_007(ctx: ActiveContext) -> tuple[Status, str]:
    payload = build_exact_eip3009_payload(ctx.requirements, ctx.signer)
    return _assert_rejected(ctx.send(tamper_recipient(payload, _ATTACKER)))


@_register(
    "RS-NEG-008",
    "Expired authorization (validBefore in past) is rejected",
    Severity.CRITICAL,
    f"{_CORE} §6.1.2 step 4",
)
def neg_008(ctx: ActiveContext) -> tuple[Status, str]:
    payload = build_exact_eip3009_payload(ctx.requirements, ctx.signer)
    return _assert_rejected(ctx.send(make_expired(payload)))


@_register(
    "RS-NEG-009",
    "Not-yet-valid authorization (validAfter in future) is rejected",
    Severity.MAJOR,
    f"{_CORE} §9 valid_after",
)
def neg_009(ctx: ActiveContext) -> tuple[Status, str]:
    payload = build_exact_eip3009_payload(ctx.requirements, ctx.signer)
    return _assert_rejected(ctx.send(make_not_yet_valid(payload)))


@_register(
    "RS-NEG-013",
    "Client-claimed lower price (accepted+value lowered) is rejected",
    Severity.CRITICAL,
    f"{_CORE} §6.1.2 step 5",
)
def neg_013(ctx: ActiveContext) -> tuple[Status, str]:
    # Pay a token amount and claim that is the price. The server must validate
    # against ITS OWN required amount, not the client-supplied `accepted`.
    cheap = {**ctx.requirements, "amount": "1"}
    payload = build_exact_eip3009_payload(cheap, ctx.signer)
    return _assert_rejected(ctx.send(payload))


@_register(
    "RS-NEG-014",
    "Payment with a wrong asset contract is rejected",
    Severity.CRITICAL,
    f"{_CORE} §6.1.2 step 4 + testcase N10",
)
def neg_014(ctx: ActiveContext) -> tuple[Status, str]:
    if ctx.requirements.get("asset", "").lower() == _OTHER_ASSET.lower():
        return Status.SKIP, "endpoint already uses the substitute test asset"
    wrong = {**ctx.requirements, "asset": _OTHER_ASSET}
    payload = build_exact_eip3009_payload(wrong, ctx.signer)
    return _assert_rejected(ctx.send(payload))


@_register(
    "RS-NEG-015",
    "Payment whose asset is an EOA (no contract code) is rejected",
    Severity.CRITICAL,
    f"{_CORE} §6.1.2 step 4 + x402#2554 asset_not_deployed_contract",
)
def neg_015(ctx: ActiveContext) -> tuple[Status, str]:
    # Distinct from RS-NEG-014 (a *different* token contract): here the asset is a
    # known EOA with no bytecode. On EVM, calling transferWithAuthorization on an
    # EOA does NOT revert — simulation passes and settlement is a silent no-op (no
    # Transfer, no funds moved), so a naive endpoint "succeeds" without being paid.
    # A correct server rejects it (asset_not_deployed_contract) before settling.
    if ctx.requirements.get("asset", "").lower() == _EOA_ASSET.lower():
        return Status.SKIP, "endpoint already advertises the EOA test asset"
    eoa = {**ctx.requirements, "asset": _EOA_ASSET}
    payload = build_exact_eip3009_payload(eoa, ctx.signer)
    return _assert_rejected(ctx.send(payload))


@_register(
    "RS-SEC-010",
    "Cross-chain signature replay (signed for another chainId) is rejected",
    Severity.CRITICAL,
    f"{_CORE} §10.1 + testcase C0",
)
def sec_010(ctx: ActiveContext) -> tuple[Status, str]:
    # Sign the authorization for a DIFFERENT chain (eip155:1) but submit it to
    # this endpoint. EIP-712 binds chainId in the domain; the endpoint verifies
    # with its own chainId, so recovery fails and the payment must be rejected.
    foreign = {**ctx.requirements, "network": "eip155:1"}
    payload = build_exact_eip3009_payload(foreign, ctx.signer)
    payload["accepted"] = dict(ctx.requirements)  # claim the endpoint's own network
    return _assert_rejected(ctx.send(payload))


@_register(
    "RS-SEC-003",
    "Cross-resource binding: a payment claiming a foreign resource is rejected",
    Severity.MINOR,
    f"{_CORE} §10.1 + arXiv:2605.11781 (III) / 2605.30998 (I3)",
)
def sec_003(ctx: ActiveContext) -> tuple[Status, str]:
    # Build a fully valid payment for THIS resource, then relabel its `resource` to a
    # different URL. EIP-3009 does not sign the resource, so the payment stays valid; a
    # server that binds payment->resource must reject the mismatch, closing the
    # cross-resource replay vector (a payment for A reused to unlock B — "missing
    # resource-identifier binding", arXiv:2605.11781 / 2605.30998).
    #
    # MINOR by design: a single request can't demonstrate the replay exploit, and the
    # resource label is unsigned metadata, so a server that ignores it isn't strictly
    # non-conformant. This is an advisory binding signal — it never gates the verdict,
    # preserving zero false-positive gating. (Overlaps the RS-NEG-013 "validate the
    # client-supplied `accepted` against your own offer" principle, applied to `resource`.)
    payload = build_exact_eip3009_payload(ctx.requirements, ctx.signer)
    payload["resource"] = {"url": _FOREIGN_RESOURCE}
    if isinstance(payload.get("accepted"), dict):
        payload["accepted"]["resource"] = _FOREIGN_RESOURCE
    resp = ctx.send(payload)
    if resp.endpoint_crashed:
        return Status.FAIL, (
            "endpoint crashed on a mismatched-resource payment "
            f"({resp.transport_error or resp.status_code})"
        )
    if resp.served_resource or resp.settled_ok:
        return Status.FAIL, (
            "served/settled a payment whose claimed `resource` differs from the requested "
            "one — no payment↔resource binding (cross-resource replay risk)"
        )
    if resp.marker_leaked:
        return Status.FAIL, "resource marker leaked on the mismatched-resource rejection path"
    return Status.PASS, f"correctly rejected a foreign-resource payment (status {resp.status_code})"


@_register(
    "RS-NEG-006",
    "Overpayment (authorized value > required) is rejected",
    Severity.MAJOR,
    f"{_CORE} §6.1.2 step 3 (exact)",
)
def neg_006(ctx: ActiveContext) -> tuple[Status, str]:
    # exact scheme: the value must equal the required amount exactly.
    dear = {**ctx.requirements, "amount": str(int(ctx.requirements["amount"]) * 2)}
    payload = build_exact_eip3009_payload(dear, ctx.signer)
    return _assert_rejected(ctx.send(payload))


@_register(
    "RS-SEC-011",
    "Extreme (near-2^256) amount is handled cleanly, not crashed",
    Severity.MINOR,
    f"{_CORE} §5.1.2 + testcase N4",
)
def sec_011(ctx: ActiveContext) -> tuple[Status, str]:
    # uint256 max — the tool must sign it without overflow and the endpoint must
    # respond cleanly: reject it (not served), never 5xx-crash on a huge value.
    huge = {**ctx.requirements, "amount": str(2**256 - 1)}
    payload = build_exact_eip3009_payload(huge, ctx.signer)
    resp = ctx.send(payload)
    if resp.status_code >= 500:
        return Status.FAIL, f"endpoint returned {resp.status_code} — crashed on an extreme amount"
    if resp.served_resource or resp.settled_ok:
        return Status.FAIL, f"endpoint accepted a near-2^256 amount (status {resp.status_code})"
    if resp.marker_leaked:
        return Status.FAIL, (
            f"resource marker leaked on the extreme-amount rejection path (status {resp.status_code})"
        )
    return Status.PASS, f"handled cleanly (status {resp.status_code})"


@_register(
    "RS-SEC-005",
    "Oversized PAYMENT-SIGNATURE header (~1 MB) is rejected cleanly, not crashed",
    Severity.MINOR,
    "transports-v2/http.md §Error Handling",
)
def sec_005(ctx: ActiveContext) -> tuple[Status, str]:
    # A ~1 MiB header value. The endpoint must reject it cleanly (a 4xx) without a
    # 5xx crash and without serving the resource — basic DoS hygiene on the header
    # path. (Length, not content: the value need not be valid base64.)
    oversized = "A" * (1024 * 1024)
    resp = ctx.send_header(oversized)
    if resp.endpoint_crashed:
        return Status.FAIL, (
            f"endpoint crashed on a ~1 MB header ({resp.transport_error or resp.status_code})"
        )
    if resp.served_resource or resp.settled_ok:
        return Status.FAIL, f"endpoint accepted a 1 MB junk header (status {resp.status_code})"
    if resp.marker_leaked:
        return Status.FAIL, (
            f"resource marker leaked on the oversized-header rejection path (status {resp.status_code})"
        )
    return Status.PASS, f"oversized header rejected cleanly (status {resp.status_code})"


@_register(
    "RS-SEC-007",
    "Control/Unicode characters in a payload field are rejected cleanly, not crashed",
    Severity.MINOR,
    "transports-v2/http.md §Error Handling",
)
def sec_007(ctx: ActiveContext) -> tuple[Status, str]:
    # Structurally valid base64+JSON, but the `from` field carries control bytes
    # and a non-ASCII char. A robust endpoint rejects it cleanly (the signature can
    # no longer recover to a mangled `from`); it must not 5xx-crash on weird input.
    payload = build_exact_eip3009_payload(ctx.requirements, ctx.signer)
    auth = payload["payload"]["authorization"]
    # NUL, RTL-override (U+202E), BEL, non-ASCII (U+00E9), built via chr() so the
    # source stays pure ASCII (no literal bidi/control chars; cf. "Trojan Source").
    auth["from"] = auth["from"] + "".join(chr(c) for c in (0x00, 0x202E, 0x07, 0xE9))
    resp = ctx.send(payload)
    if resp.endpoint_crashed:
        return (
            Status.FAIL,
            "endpoint crashed on control/Unicode chars in a payload field "
            f"({resp.transport_error or resp.status_code})",
        )
    return _assert_rejected(resp)


@_register(
    "RS-SEC-006",
    "Header smuggling: an invalid payment is not let through by a contradictory legacy V1 header",
    Severity.MINOR,
    "transports-v2/http.md §Header Summary",
)
def sec_006(ctx: ActiveContext) -> tuple[Status, str]:
    import base64
    import json as _json

    # Send an INVALID v2 payment (tampered signature) AND a legacy V1 `X-PAYMENT` header.
    # If parser/proxy ambiguity lets the legacy header smuggle the request past v2
    # validation (arXiv:2605.11781 Attack III), a naive endpoint serves/settles despite
    # the invalid v2 payment. A correct endpoint rejects it regardless of the extra
    # header, and must not 5xx-crash on the duplicate/contradictory headers.
    bad = tamper_signature(build_exact_eip3009_payload(ctx.requirements, ctx.signer))
    legacy_v1 = base64.b64encode(
        _json.dumps({"x402Version": 1, "scheme": "exact", "network": "base-sepolia"}).encode()
    ).decode()
    resp = ctx.send_with_headers(bad, {"X-PAYMENT": legacy_v1})
    if resp.endpoint_crashed:
        return (
            Status.FAIL,
            "endpoint crashed on dual v2+legacy-V1 headers "
            f"({resp.transport_error or resp.status_code})",
        )
    return _assert_rejected(resp)


@_register(
    "RS-SEC-004",
    "Payment with a non-32-byte nonce is rejected cleanly, not crashed",
    Severity.MAJOR,
    f"{_CORE} §5.2.2 invalid nonce",
)
def sec_004(ctx: ActiveContext) -> tuple[Status, str]:
    # The EIP-3009 nonce is a bytes32. A non-32-byte nonce is malformed (and breaks
    # replay protection); the endpoint must reject it cleanly, never 5xx-crash on a
    # naive bytes32 parse. (Reuse of a *valid* nonce is the stateful on-chain replay
    # case, RS-SEC-001.)
    payload = build_exact_eip3009_payload(ctx.requirements, ctx.signer)
    payload["payload"]["authorization"]["nonce"] = "0x1234"  # 2 bytes, not 32
    resp = ctx.send(payload)
    if resp.status_code >= 500:
        return Status.FAIL, f"endpoint returned {resp.status_code} — crashed on a non-32-byte nonce"
    return _assert_rejected(resp)


@_register(
    "RS-NEG-011",
    "Payment whose `accepted` claims a scheme/network the server never offered is rejected",
    Severity.MAJOR,
    f"{_CORE} §9 invalid_network",
)
def neg_011(ctx: ActiveContext) -> tuple[Status, str]:
    # The client echoes an `accepted` entry on a network the endpoint does not
    # offer. The server must match the payment to one of its own requirements and
    # reject the mismatch (invalid_scheme/invalid_network), not serve blindly.
    payload = build_exact_eip3009_payload(ctx.requirements, ctx.signer)
    payload["accepted"] = {**dict(ctx.requirements), "network": "eip155:999999"}
    return _assert_rejected(ctx.send(payload))


@_register(
    "RS-NEG-012",
    "Payment with x402Version != 2 is rejected",
    Severity.MAJOR,
    f"{_CORE} §9 invalid_x402_version",
)
def neg_012(ctx: ActiveContext) -> tuple[Status, str]:
    # A v2 endpoint must reject an unknown top-level x402Version (here 99) cleanly,
    # not mis-parse it. (1 may legitimately route to a V1 fallback; 99 is
    # unambiguously unsupported, so the verdict stays "must reject".)
    payload = build_exact_eip3009_payload(ctx.requirements, ctx.signer)
    payload["x402Version"] = 99
    return _assert_rejected(ctx.send(payload))


def evaluate_active(context: ActiveContext | None) -> list[CheckResult]:
    """Run every active check; skip all cleanly if no payable requirement found."""
    results: list[CheckResult] = []
    for check in ACTIVE_REGISTRY:
        if context is None:
            status, detail = Status.SKIP, "no exact/eip3009 requirement to attack"
        else:
            try:
                status, detail = check.func(context)
            except Exception as exc:  # a crashing check is OUR bug, never the target's
                status, detail = Status.ERROR, f"check crashed (suite bug): {exc!r}"
        results.append(
            CheckResult(
                check_id=check.check_id,
                title=check.title,
                severity=check.severity,
                spec_ref=check.spec_ref,
                status=status,
                detail=detail,
            )
        )
    return results
