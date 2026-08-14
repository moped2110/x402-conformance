"""Opt-in PQC-001..006 checks for hybrid facilitator receipts."""

from __future__ import annotations

import base64
import binascii
import copy
import json
from collections.abc import Callable

from ..probe import ProbeSession
from ..safety import require_pqc_test_key_network
from .base import Check, CheckFunc, Severity, Status, append_unique_check

_SPEC = "PSV PQC-Belegformat v2"
_DOMAIN = b"PSV-RECEIPT-V2\x00"
_CLASSICAL = "ECDSA-P256-SHA256"
_PQC = "ML-DSA-65"

PQC_REGISTRY: list[Check] = []


def _register(
    check_id: str, title: str, severity: Severity, spec_ref: str
) -> Callable[[CheckFunc], CheckFunc]:
    """Register one check in the explicitly selected PQC group."""

    def decorator(func: CheckFunc) -> CheckFunc:
        """Add the decorated check while rejecting duplicate IDs."""
        append_unique_check(
            PQC_REGISTRY, Check(check_id, title, severity, spec_ref, func), check_id
        )
        return func

    return decorator


def _capability(session: ProbeSession) -> dict[str, object] | None:
    raw = session.first.raw
    extensions = raw.get("extensions") if isinstance(raw, dict) else None
    value = extensions.get("pqc") if isinstance(extensions, dict) else None
    return value if isinstance(value, dict) else None


def _receipt(session: ProbeSession) -> dict[str, object] | None:
    capability = _capability(session)
    value = capability.get("receipt") if capability is not None else None
    return value if isinstance(value, dict) else None


def _decode(value: object) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise ValueError("signature/key must be non-empty unpadded base64url")
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid base64url") from exc


def _parts(
    session: ProbeSession,
) -> tuple[dict[str, object], dict[str, object], dict[str, object], dict[str, object]]:
    capability = _capability(session)
    receipt = _receipt(session)
    if capability is None or receipt is None:
        raise ValueError("PQC capability or receipt missing")
    sig_v2 = receipt.get("sig_v2")
    if not isinstance(sig_v2, dict) or set(sig_v2) != {"version", "classical", "pqc"}:
        raise ValueError("sig_v2 has an invalid structure")
    classical = sig_v2.get("classical")
    pqc = sig_v2.get("pqc")
    if not isinstance(classical, dict) or not isinstance(pqc, dict):
        raise ValueError("both signature entries are required")
    return receipt, sig_v2, classical, pqc


def _canonical(receipt: dict[str, object]) -> bytes:
    unsigned = copy.deepcopy(receipt)
    sig_v2 = unsigned["sig_v2"]
    if not isinstance(sig_v2, dict):
        raise ValueError("sig_v2 must be an object")
    for name in ("classical", "pqc"):
        entry = sig_v2.get(name)
        if not isinstance(entry, dict):
            raise ValueError("signature entry must be an object")
        entry["signature"] = ""
    return _DOMAIN + json.dumps(
        unsigned, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False
    ).encode("utf-8")


def _keys(session: ProbeSession) -> tuple[bytes, bytes]:
    capability = _capability(session)
    receipt, _sig_v2, classical, pqc = _parts(session)
    keys = capability.get("keys") if capability is not None else None
    if not isinstance(keys, dict):
        raise ValueError("PQC public-key registry missing")
    network = receipt.get("network")
    result: list[bytes] = []
    for entry in (classical, pqc):
        kid = entry.get("kid")
        if not isinstance(kid, str) or not kid or len(kid) > 128:
            raise ValueError("invalid key ID")
        require_pqc_test_key_network(kid, network)
        result.append(_decode(keys.get(kid)))
    return result[0], result[1]


def _verify(session: ProbeSession, receipt: dict[str, object] | None = None) -> tuple[bool, bool]:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, mldsa

    current = _receipt(session) if receipt is None else receipt
    if current is None:
        raise ValueError("receipt missing")
    _original, _sig_v2, classical, pqc = _parts(session)
    if receipt is not None:
        changed = current.get("sig_v2")
        if not isinstance(changed, dict):
            raise ValueError("sig_v2 missing")
        classical = changed.get("classical")  # type: ignore[assignment]
        pqc = changed.get("pqc")  # type: ignore[assignment]
        if not isinstance(classical, dict) or not isinstance(pqc, dict):
            raise ValueError("signature entries missing")
    classical_key, pqc_key = _keys(session)
    payload = _canonical(current)
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), classical_key).verify(
            _decode(classical.get("signature")), payload, ec.ECDSA(hashes.SHA256())
        )
        classical_valid = True
    except (InvalidSignature, ValueError):
        classical_valid = False
    try:
        mldsa.MLDSA65PublicKey.from_public_bytes(pqc_key).verify(
            _decode(pqc.get("signature")), payload
        )
        pqc_valid = True
    except (InvalidSignature, ValueError):
        pqc_valid = False
    return classical_valid, pqc_valid


@_register("PQC-001", "PQC capability is advertised correctly", Severity.MAJOR, _SPEC)
def pqc_001(session: ProbeSession) -> tuple[Status, str]:
    """Validate the closed capability contract in the 402 response."""
    capability = _capability(session)
    if capability is None:
        return Status.FAIL, "extensions.pqc capability missing"
    required = {"version", "algorithms", "receipt", "verifyUrl", "keys"}
    if set(capability) != required or capability.get("version") != 2:
        return Status.FAIL, "PQC capability is not schema-valid"
    if capability.get("algorithms") != [_CLASSICAL, _PQC]:
        return Status.FAIL, "PQC capability must advertise the fixed v2 algorithm registry"
    if not isinstance(capability.get("verifyUrl"), str) or not capability["verifyUrl"]:
        return Status.FAIL, "PQC verifyUrl missing"
    return Status.PASS, "schema-valid receipt-v2 PQC capability advertised"


@_register("PQC-002", "Hybrid receipt structure is valid", Severity.MAJOR, _SPEC)
def pqc_002(session: ProbeSession) -> tuple[Status, str]:
    """Validate signature entries, registry IDs, key IDs, and ML-DSA length."""
    try:
        _receipt_value, sig_v2, classical, pqc = _parts(session)
        if sig_v2.get("version") != 2:
            raise ValueError("sig_v2.version must be 2")
        for entry, algorithm in ((classical, _CLASSICAL), (pqc, _PQC)):
            if set(entry) != {"alg", "kid", "signature"} or entry.get("alg") != algorithm:
                raise ValueError("unregistered algorithm or malformed signature entry")
            kid = entry.get("kid")
            if not isinstance(kid, str) or not kid or len(kid) > 128:
                raise ValueError("implausible key ID")
        if len(_decode(pqc.get("signature"))) != 3309:
            raise ValueError("ML-DSA-65 signature must be exactly 3309 bytes")
        classical_key, pqc_key = _keys(session)
        if len(classical_key) != 65 or len(pqc_key) != 1952:
            raise ValueError("public key length does not match the algorithm")
    except ValueError as exc:
        return Status.FAIL, str(exc)
    return Status.PASS, "hybrid receipt has the registered v2 structure and lengths"


@_register("PQC-003", "Both hybrid signatures are valid", Severity.CRITICAL, _SPEC)
def pqc_003(session: ProbeSession) -> tuple[Status, str]:
    """Require the classical and ML-DSA signatures as an AND composition."""
    try:
        classical, pqc = _verify(session)
    except (ImportError, ValueError) as exc:
        return Status.FAIL, f"hybrid verification unavailable: {exc}"
    if not (classical and pqc):
        return Status.FAIL, f"AND verification failed (classical={classical}, pqc={pqc})"
    return Status.PASS, "classical and ML-DSA-65 signatures are valid"


@_register("PQC-004", "Tampered ML-DSA signature is rejected", Severity.CRITICAL, _SPEC)
def pqc_004(session: ProbeSession) -> tuple[Status, str]:
    """Catch verifiers that carry PQC decoratively but validate only classical."""
    response = session.pqc_tamper_response
    if response is None:
        return Status.FAIL, "PQC verifier probe was unavailable"
    if response.get("accepted") is not False:
        return Status.FAIL, "SUT accepted a receipt with a tampered ML-DSA-65 signature"
    return Status.PASS, "SUT rejected the tampered ML-DSA-65 signature"


@_register("PQC-005", "PQC downgrade is rejected or explicit", Severity.CRITICAL, _SPEC)
def pqc_005(session: ProbeSession) -> tuple[Status, str]:
    """Reject silent stripping while allowing an explicit degraded verdict."""
    response = session.pqc_downgrade_response
    if response is None:
        return Status.FAIL, "PQC downgrade probe was unavailable"
    if response.get("accepted") is False:
        return Status.PASS, "SUT rejected the stripped sig_v2 downgrade"
    if response.get("accepted") is True and response.get("degraded") is True:
        return Status.PASS, "SUT accepted only with an explicit degraded flag"
    return Status.FAIL, "SUT silently accepted a stripped sig_v2 receipt"


@_register("PQC-006", "Algorithm metadata is cross-signed", Severity.CRITICAL, _SPEC)
def pqc_006(session: ProbeSession) -> tuple[Status, str]:
    """Prove that changing algorithm metadata invalidates both signatures."""
    receipt = _receipt(session)
    if receipt is None:
        return Status.FAIL, "receipt missing"
    try:
        original_classical, original_pqc = _verify(session)
    except (ImportError, ValueError) as exc:
        return Status.FAIL, f"cross-signing check unavailable: {exc}"
    if not (original_classical and original_pqc):
        return Status.FAIL, "original receipt is not valid under both signatures"
    changed = copy.deepcopy(receipt)
    sig_v2 = changed.get("sig_v2")
    if not isinstance(sig_v2, dict) or not isinstance(sig_v2.get("pqc"), dict):
        return Status.FAIL, "sig_v2.pqc missing"
    sig_v2["pqc"]["alg"] = "ML-DSA-44"
    try:
        classical, pqc = _verify(session, changed)
    except (ImportError, ValueError) as exc:
        return Status.FAIL, f"cross-signing check unavailable: {exc}"
    if classical or pqc:
        return Status.FAIL, "algorithm metadata is not covered by both signatures"
    return Status.PASS, "changing algorithm metadata invalidates both signatures"
