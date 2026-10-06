"""Opt-in PQC-001..006 checks for hybrid facilitator receipts (catalog §11)."""

from __future__ import annotations

import base64
import binascii
import copy
import json
from collections.abc import Callable

from ..probe import ProbeSession
from ..safety import require_pqc_test_key_network
from .base import Check, CheckFunc, Severity, Status, append_unique_check

_SPEC = "PSV receipt-v2"
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
    """Return the `extensions.pqc` capability object from the first 402, if it is an object."""
    raw = session.first.raw
    extensions = raw.get("extensions") if isinstance(raw, dict) else None
    value = extensions.get("pqc") if isinstance(extensions, dict) else None
    return value if isinstance(value, dict) else None


def _receipt(session: ProbeSession) -> dict[str, object] | None:
    """Return the sample receipt advertised inside the PQC capability, if it is an object."""
    capability = _capability(session)
    value = capability.get("receipt") if capability is not None else None
    return value if isinstance(value, dict) else None


def _decode(value: object) -> bytes:
    """Decode non-empty, unpadded base64url; raise ``ValueError`` on anything else."""
    if not isinstance(value, str) or not value or "=" in value:
        raise ValueError("signature/key must be non-empty unpadded base64url")
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid base64url") from exc


def _parts(
    session: ProbeSession,
) -> tuple[dict[str, object], dict[str, object], dict[str, object], dict[str, object]]:
    """Split the advertised receipt into receipt, `sig_v2`, classical and PQC entries.

    Raises ``ValueError`` unless `sig_v2` has exactly the closed v2 structure.
    """
    capability = _capability(session)
    receipt = _receipt(session)
    if capability is None or receipt is None:
        raise ValueError("PQC capability or receipt missing")
    duplicate = _receipt_duplicate_member(session)
    if duplicate is not None:
        raise ValueError(f"duplicate JSON member: {duplicate}")
    sig_v2 = receipt.get("sig_v2")
    if not isinstance(sig_v2, dict) or set(sig_v2) != {"version", "classical", "pqc"}:
        raise ValueError("sig_v2 has an invalid structure")
    classical = sig_v2.get("classical")
    pqc = sig_v2.get("pqc")
    if not isinstance(classical, dict) or not isinstance(pqc, dict):
        raise ValueError("both signature entries are required")
    return receipt, sig_v2, classical, pqc


def _canonical(receipt: dict[str, object]) -> bytes:
    """Return the domain-separated bytes both signatures cover.

    Both `signature` values are blanked and the rest is serialized as compact, key-sorted
    UTF-8 JSON behind the `PSV-RECEIPT-V2\\x00` tag, matching psv's `canonical_receipt_payload`.
    """
    unsigned = copy.deepcopy(receipt)
    sig_v2 = unsigned["sig_v2"]
    if not isinstance(sig_v2, dict):
        raise ValueError("sig_v2 must be an object")
    for name in ("classical", "pqc"):
        entry = sig_v2.get(name)
        if not isinstance(entry, dict):
            raise ValueError("signature entry must be an object")
        entry["signature"] = ""
    _validate_json_profile(unsigned)
    try:
        encoded = json.dumps(
            unsigned, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("receipt is not canonicalizable JSON") from exc
    return _DOMAIN + encoded


def _validate_json_profile(value: object) -> None:
    """Reject values whose cross-language canonical encoding would be ambiguous.

    A verbatim port of psv's ``_validate_json_profile`` with the same messages: ASCII
    string keys only, no floats (amounts travel as decimal strings), JSON types only.
    """
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise ValueError("receipt object keys must be ASCII strings")
            _validate_json_profile(child)
    elif isinstance(value, list):
        for child in value:
            _validate_json_profile(child)
    elif isinstance(value, float):
        raise ValueError("receipt numbers must be integers; decimal amounts use strings")
    elif value is not None and not isinstance(value, (bool, int, str)):
        raise ValueError("receipt contains a non-JSON value")


class _MemberRecord(dict[str, object]):
    """A decoded JSON object that remembers the first member name it saw twice."""

    duplicate: str | None = None


def _record_members(pairs: list[tuple[str, object]]) -> _MemberRecord:
    """Build an object last-wins, as ``json`` does, noting the first repeated name."""
    result = _MemberRecord()
    for key, value in pairs:
        if key in result and result.duplicate is None:
            result.duplicate = key
        result[key] = value
    return result


def _first_duplicate(value: object) -> str | None:
    """Return the first repeated member name anywhere inside a decoded value."""
    if isinstance(value, _MemberRecord) and value.duplicate is not None:
        return value.duplicate
    children: list[object]
    if isinstance(value, dict):
        children = list(value.values())
    elif isinstance(value, list):
        children = value
    else:
        return None
    for child in children:
        found = _first_duplicate(child)
        if found is not None:
            return found
    return None


def _receipt_duplicate_member(session: ProbeSession) -> str | None:
    """Find a repeated member name inside the advertised receipt's JSON text.

    The probe parses the challenge last-wins, so a duplicate is gone by the time the
    receipt is a dict. psv parses receipts with a hook that rejects duplicates, so the
    challenge text is re-read here and only the receipt subtree is inspected: a repeated
    key elsewhere in the challenge is another check's business.
    """
    decoded = session.first.decoded
    if decoded is None:
        return None
    try:
        document = json.loads(decoded, object_pairs_hook=_record_members)
    except (ValueError, RecursionError):
        return None
    extensions = document.get("extensions") if isinstance(document, dict) else None
    pqc = extensions.get("pqc") if isinstance(extensions, dict) else None
    receipt = pqc.get("receipt") if isinstance(pqc, dict) else None
    return _first_duplicate(receipt) if isinstance(receipt, dict) else None


def _keys(session: ProbeSession) -> tuple[bytes, bytes]:
    """Resolve both key IDs against the advertised public-key registry.

    Marked test-fixture key IDs are refused outside the testnet/local allowlist before any
    key is decoded. Returns the classical and the PQC public key bytes.
    """
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
    """Verify a receipt's ECDSA-P256 and ML-DSA-65 signatures independently.

    Uses the advertised receipt unless ``receipt`` (e.g. a tampered copy) is given, and
    returns ``(classical_valid, pqc_valid)`` so callers can enforce the AND-composition.
    """
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
    """Validate signature entries, registry IDs, key IDs, ML-DSA length and JSON profile."""
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
        _canonical(_receipt_value)
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
