"""RS-PR: PaymentRequired content checks (catalog §2).

These run on the decoded PAYMENT-REQUIRED payload of the first probe and skip
cleanly when the handshake itself already failed.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from ..jp402 import (
    find_invoice_blocks,
    find_jp402,
    find_jp402_accept,
    validate_invoice,
    validate_tax,
)
from ..probe import ProbeSession
from .base import Severity, Status, register

_CORE = "x402-specification-v2.md"

# CAIP-2: namespace 3-8 chars [-a-z0-9], reference 1-32 chars [-_a-zA-Z0-9]
_CAIP2_RE = re.compile(r"^[a-z0-9-]{3,8}:[-_a-zA-Z0-9]{1,32}$")
_ATOMIC_AMOUNT_RE = re.compile(r"^[0-9]+$")
_EVM_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_PRINTABLE_ASCII_RE = re.compile(r"^[\x20-\x7e]*$")

_REQUIRED_ACCEPT_FIELDS = ("scheme", "network", "amount", "asset", "payTo", "maxTimeoutSeconds")

# The complete v2 PaymentRequirements vocabulary for one accepts entry
# (CORE §5.1.2): the six required fields plus the optional `extra`. `resource`,
# `description`, and `mimeType` are top-level ResourceInfo, not per-entry.
_KNOWN_ACCEPT_FIELDS = frozenset({*_REQUIRED_ACCEPT_FIELDS, "extra"})

# Payment schemes the protocol names (CORE §6). `auth-capture` has had a spec
# directory for a while but was only named in the core list in 2026-08; it is a
# real wire scheme (`"scheme": "auth-capture"`, specs/schemes/auth-capture/) and
# leaving it out made RS-PR-017 call a conformant endpoint unpayable.
_KNOWN_SCHEMES = frozenset({"exact", "upto", "batch-settlement", "auth-capture"})

#: Keys the *protocol* reserves inside `PaymentRequirements.extra` (CORE §6.1).
#: These are not scheme-private: a mechanism declares its supported payment flows
#: per `assetTransferMethod`, and the spec names `upto` explicitly when explaining
#: why — "distinguishing an SVM upto `escrow` default from an EVM upto
#: `authorization` default". So they are legal on any scheme and must never be
#: graded as a foreign key.
_RESERVED_EXTRA_KEYS = frozenset({"assetTransferMethod", "paymentFlow"})

# Scheme-specific `extra` vocabularies, from the scheme specs. `exact` on EVM
# (scheme_exact_evm.md) uses the EIP-712 domain fields; `upto` on SVM
# (scheme_upto_svm.md) uses the payment-channel fields. A key from one scheme
# appearing on an entry declaring the other is a scheme/extra mismatch — but the
# reserved keys above belong to neither vocabulary and are excluded from both.
_EXACT_EXTRA_KEYS = frozenset({"name", "version"})
_UPTO_EXTRA_KEYS = frozenset(
    {
        "feePayer",
        "receiverAuthorizer",
        "withdrawDelay",
        "tokenProgram",
        "recentBlockhash",
        "recentSlot",
        "validAfter",
    }
)

#: The payment flow models defined in CORE §6.1. `authorization` verifies before
#: the resource runs and settles after; `upfront` and `escrow` commit funds
#: *before* it runs.
_PAYMENT_FLOWS = frozenset({"authorization", "upfront", "escrow"})

#: Flows that bind the payer's money before the resource executes. The spec
#: requires these to be declared explicitly so a client can see the commitment
#: coming without knowing the mechanism.
_PRE_HANDLER_FLOWS = frozenset({"upfront", "escrow"})

#: `extra` fields that only exist because a mechanism holds or escrows funds
#: before the resource runs: the SVM `upto` channel controls
#: (scheme_upto_svm.md) and the `auth-capture` capture switch
#: (scheme_auth_capture.md). Their presence is the observable hint that this
#: entry is not plain post-handler settlement.
_ESCROW_EXTRA_SIGNALS = frozenset({"withdrawDelay", "receiverAuthorizer", "autoCapture"})


def _hkey(v: object) -> object:
    """Return a hashable stand-in for grouping: the value itself, or its repr."""
    try:
        hash(v)
    except TypeError:
        return repr(v)
    return v


def _accepts_raw(s: ProbeSession) -> list[dict[str, object]] | None:
    """Return only object entries from the raw accepts array, or None for a missing array."""
    if s.first.raw is None:
        return None
    accepts = s.first.raw.get("accepts")
    if not isinstance(accepts, list):
        return None
    return [a for a in accepts if isinstance(a, dict)]


# x402 v1 is a recognized PRIOR protocol version that real deployments still emit
# (e.g. some JPYC facilitators). This suite tests v2, so a v1 endpoint should read
# as "speaks v1, not v2" — bucketed under RS-PR-001 — rather than accruing generic
# v2-shape failures that wrongly flip the verdict to NOT CONFORMANT. The v2-shape
# checks (RS-PR-001/002/005 + RS-HS-004) skip on a recognised v1 envelope; the
# version-agnostic rail checks (network/asset/amount/extra) still run.
_V1_SKIP = "endpoint advertises x402 v1, not v2 — this suite tests v2 (see RS-PR-001)"


def _x402_version(s: ProbeSession) -> object:
    """Read the uncoerced x402Version value from the raw challenge."""
    return s.first.raw.get("x402Version") if s.first.raw is not None else None


def _resource_identity(url: str) -> tuple[str, str, int, str, str] | None:
    """Canonical HTTP resource identity without weakening scheme or query binding."""
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or host is None or parsed.username is not None:
        return None
    effective_port = port if port is not None else (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/")
    return scheme, host.lower(), effective_port, path, parsed.query


@register("RS-PR-001", "x402Version present and == 2", Severity.MAJOR, f"{_CORE} §5.1.2")
def pr_001(s: ProbeSession) -> tuple[Status, str]:
    """Evaluate RS-PR-001: x402Version present and == 2."""
    if s.first.raw is None:
        return Status.SKIP, "no decoded PaymentRequired payload"
    version = s.first.raw.get("x402Version")
    if version == 2:
        return Status.PASS, ""
    if version == 1:
        return Status.SKIP, (
            "endpoint advertises x402 v1, a recognized prior protocol version — "
            "this suite tests v2, so v2-shape checks are skipped; the version-agnostic "
            "rail checks (network/asset/amount/extra) still ran"
        )
    return Status.FAIL, f"x402Version is {version!r}, expected 2"


@register(
    "RS-PR-002", "resource object present with required url", Severity.MAJOR, f"{_CORE} §5.1.2"
)
def pr_002(s: ProbeSession) -> tuple[Status, str]:
    """Evaluate RS-PR-002: resource object present with required url."""
    if s.first.raw is None:
        return Status.SKIP, "no decoded PaymentRequired payload"
    if _x402_version(s) == 1:
        return Status.SKIP, _V1_SKIP
    resource = s.first.raw.get("resource")
    if not isinstance(resource, dict):
        return Status.FAIL, "resource object missing"
    if not isinstance(resource.get("url"), str) or not resource["url"]:
        return Status.FAIL, "resource.url missing or empty"
    return Status.PASS, ""


@register(
    "RS-PR-003",
    "resource.url matches the requested resource",
    Severity.MAJOR,
    f"{_CORE} §5.1.2",
)
def pr_003(s: ProbeSession) -> tuple[Status, str]:
    """Evaluate RS-PR-003: resource.url matches the requested resource."""
    if s.first.parsed is None:
        return Status.SKIP, "no parsed PaymentRequired payload"
    advertised = _resource_identity(s.first.parsed.resource.url)
    requested = _resource_identity(s.target_url)
    if advertised is not None and advertised == requested:
        return Status.PASS, ""
    return Status.FAIL, (
        f"advertised resource.url {s.first.parsed.resource.url!r} does not match "
        f"requested {s.target_url!r} — clients may refuse or be misled"
    )


@register("RS-PR-004", "accepts array present with >= 1 entry", Severity.MAJOR, f"{_CORE} §5.1.2")
def pr_004(s: ProbeSession) -> tuple[Status, str]:
    """Evaluate RS-PR-004: accepts array present with >= 1 entry."""
    if s.first.raw is None:
        return Status.SKIP, "no decoded PaymentRequired payload"
    accepts = _accepts_raw(s)
    if accepts is None:
        return Status.FAIL, "accepts missing or not an array"
    if len(accepts) == 0:
        return Status.FAIL, "accepts is empty — no way to pay"
    return Status.PASS, ""


@register(
    "RS-PR-005",
    "Every accepts entry carries all required fields",
    Severity.MAJOR,
    f"{_CORE} §5.1.2",
)
def pr_005(s: ProbeSession) -> tuple[Status, str]:
    """Evaluate RS-PR-005: Every accepts entry carries all required fields."""
    if _x402_version(s) == 1:
        return Status.SKIP, _V1_SKIP
    accepts = _accepts_raw(s)
    if not accepts:
        return Status.SKIP, "no accepts entries to inspect"
    problems = []
    for i, entry in enumerate(accepts):
        missing = [f for f in _REQUIRED_ACCEPT_FIELDS if f not in entry]
        if missing:
            problems.append(f"accepts[{i}] missing: {', '.join(missing)}")
    if problems:
        return Status.FAIL, "; ".join(problems)
    return Status.PASS, ""


@register("RS-PR-006", "network is valid CAIP-2", Severity.MAJOR, f"{_CORE} §11.1")
def pr_006(s: ProbeSession) -> tuple[Status, str]:
    """Evaluate RS-PR-006: network is valid CAIP-2."""
    accepts = _accepts_raw(s)
    if not accepts:
        return Status.SKIP, "no accepts entries to inspect"
    bad = []
    for e in accepts:
        network = e.get("network")
        if not (isinstance(network, str) and _CAIP2_RE.match(network)):
            bad.append(repr(network))
    if bad:
        return Status.FAIL, f"non-CAIP-2 network identifier(s): {', '.join(bad)}"
    return Status.PASS, ""


@register(
    "RS-PR-007",
    "amount is an integer string in atomic units",
    Severity.MAJOR,
    f"{_CORE} §5.1.2",
)
def pr_007(s: ProbeSession) -> tuple[Status, str]:
    """Evaluate RS-PR-007: amount is an integer string in atomic units."""
    accepts = _accepts_raw(s)
    if not accepts:
        return Status.SKIP, "no accepts entries to inspect"
    bad = []
    for i, e in enumerate(accepts):
        amount = e.get("amount")
        if not isinstance(amount, str):
            bad.append(f"accepts[{i}].amount is {type(amount).__name__}, must be string")
        elif not _ATOMIC_AMOUNT_RE.match(amount):
            bad.append(f"accepts[{i}].amount {amount!r} is not an atomic integer string")
    if bad:
        return Status.FAIL, "; ".join(bad)
    return Status.PASS, ""


@register(
    "RS-PR-008",
    "EVM asset is a well-formed contract address",
    Severity.MINOR,
    f"{_CORE} §5.1.2 + scheme_exact_evm.md",
)
def pr_008(s: ProbeSession) -> tuple[Status, str]:
    """Evaluate RS-PR-008: EVM asset is a well-formed contract address."""
    accepts = _accepts_raw(s)
    if not accepts:
        return Status.SKIP, "no accepts entries to inspect"
    evm = []
    for e in accepts:
        network = e.get("network")
        if isinstance(network, str) and network.startswith("eip155:"):
            evm.append(e)
    if not evm:
        return Status.SKIP, "no EVM accepts entries"
    bad = []
    for e in evm:
        asset = e.get("asset")
        if not (isinstance(asset, str) and _EVM_ADDRESS_RE.match(asset)):
            bad.append(repr(asset))
    if bad:
        return Status.FAIL, f"malformed EVM asset address(es): {', '.join(bad)}"

    # EIP-55: a mixed-case address carries a checksum that must verify. An
    # all-lower/all-upper address is unchecksummed (a legitimate form) — nothing
    # to validate. Needs keccak (eth_utils); without it, fall back to format-only.
    assets = [str(e.get("asset")) for e in evm]
    try:
        from eth_utils import is_checksum_address  # type: ignore[attr-defined]
    except Exception:
        return Status.PASS, "format ok (EIP-55 not checked: install [evm] for keccak)"
    mixed = [a for a in assets if a[2:] != a[2:].lower() and a[2:] != a[2:].upper()]
    invalid = [a for a in mixed if not is_checksum_address(a)]
    if invalid:
        return Status.FAIL, f"bad EIP-55 checksum: {', '.join(invalid)}"
    if mixed:
        return Status.PASS, f"EIP-55 checksum valid ({len(mixed)} mixed-case)"
    return Status.PASS, "format ok (addresses unchecksummed/lowercase)"


@register(
    "RS-PR-009",
    "exact/eip3009 entries carry extra.name and extra.version (EIP-712 domain)",
    Severity.MAJOR,
    "scheme_exact_evm.md §1 extra fields",
)
def pr_009(s: ProbeSession) -> tuple[Status, str]:
    """Evaluate RS-PR-009: exact/eip3009 entries carry extra.name and extra.version (EIP-712 domain)."""
    accepts = _accepts_raw(s)
    if not accepts:
        return Status.SKIP, "no accepts entries to inspect"
    relevant: list[tuple[int, dict[str, object]]] = []
    for i, e in enumerate(accepts):
        if e.get("scheme") != "exact":
            continue
        network = e.get("network")
        if not (isinstance(network, str) and network.startswith("eip155:")):
            continue
        raw_extra = e.get("extra")
        extra: dict[str, object] = raw_extra if isinstance(raw_extra, dict) else {}
        if extra.get("assetTransferMethod", "eip3009") == "eip3009":
            relevant.append((i, extra))
    if not relevant:
        return Status.SKIP, "no exact/eip3009 EVM entries"
    problems = []
    for i, extra in relevant:
        missing = [k for k in ("name", "version") if not extra.get(k)]
        if missing:
            problems.append(f"accepts[{i}].extra missing: {', '.join(missing)}")
    if problems:
        return Status.FAIL, (
            "; ".join(problems) + " — clients cannot build the EIP-712 signature without these"
        )
    return Status.PASS, ""


@register(
    "RS-PR-010",
    "ResourceInfo constraints (serviceName/tags/iconUrl limits)",
    Severity.MINOR,
    f"{_CORE} §5.1.2 ResourceInfo",
)
def pr_010(s: ProbeSession) -> tuple[Status, str]:
    """Evaluate RS-PR-010: ResourceInfo constraints (serviceName/tags/iconUrl limits)."""
    if s.first.parsed is None:
        return Status.SKIP, "no parsed PaymentRequired payload"
    r = s.first.parsed.resource
    problems = []
    if r.service_name is not None and (
        len(r.service_name) > 32 or not _PRINTABLE_ASCII_RE.match(r.service_name)
    ):
        problems.append("serviceName violates 'printable ASCII, max 32 chars'")
    if r.tags is not None:
        if len(r.tags) > 5:
            problems.append(f"tags has {len(r.tags)} entries (max 5)")
        for t in r.tags:
            if len(t) > 32 or not _PRINTABLE_ASCII_RE.match(t):
                problems.append(f"tag {t!r} violates 'printable ASCII, max 32 chars'")
    if r.icon_url is not None:
        if len(r.icon_url) > 2048:
            problems.append("iconUrl exceeds 2048 chars")
        elif not r.icon_url.startswith(("https://", "http://")):
            problems.append("iconUrl is not an absolute http(s) URL")
    if problems:
        return Status.FAIL, "; ".join(problems)
    return Status.PASS, ""


@register(
    "RS-PR-011",
    "extensions entries each carry info and schema",
    Severity.MINOR,
    f"{_CORE} §5.1.2 Extensions",
)
def pr_011(s: ProbeSession) -> tuple[Status, str]:
    """Evaluate RS-PR-011: extensions entries each carry info and schema."""
    if s.first.raw is None:
        return Status.SKIP, "no decoded PaymentRequired payload"
    extensions = s.first.raw.get("extensions")
    if extensions is None or extensions == {}:
        return Status.SKIP, "no extensions advertised"
    if not isinstance(extensions, dict):
        return Status.FAIL, "extensions is not an object"
    problems = []
    for key, value in extensions.items():
        if not isinstance(value, dict):
            problems.append(f"extensions[{key!r}] is not an object")
            continue
        missing = [k for k in ("info", "schema") if k not in value]
        if missing:
            problems.append(f"extensions[{key!r}] missing: {', '.join(missing)}")
    if problems:
        return Status.FAIL, "; ".join(problems)
    # NOTE: structural check only; validating info against schema comes later.
    return Status.PASS, "structural check only (info-vs-schema validation pending)"


@register(
    "RS-PR-012",
    "Payment requirements stable across identical unpaid requests",
    Severity.MINOR,
    f"{_CORE} §5.1",
)
def pr_012(s: ProbeSession) -> tuple[Status, str]:
    """Evaluate RS-PR-012: Payment requirements stable across identical unpaid requests."""
    if s.second is None or s.first.raw is None or s.second.raw is None:
        return Status.SKIP, "need two decodable probes to compare"
    if s.first.raw.get("accepts") == s.second.raw.get("accepts"):
        return Status.PASS, ""
    return Status.FAIL, (
        "accepts differ between two identical unpaid requests — "
        "dynamic pricing is allowed but should be deliberate and documented"
    )


@register(
    "RS-PR-013",
    "payTo/asset match the network's CAIP-2 namespace",
    Severity.MAJOR,
    f"{_CORE} §11.1 + testcase N1/N2",
)
def pr_013(s: ProbeSession) -> tuple[Status, str]:
    """Evaluate RS-PR-013: payTo/asset match the network's CAIP-2 namespace."""
    accepts = _accepts_raw(s)
    if not accepts:
        return Status.SKIP, "no accepts entries to inspect"
    problems = []
    for i, e in enumerate(accepts):
        network = e.get("network")
        if not isinstance(network, str) or ":" not in network:
            continue  # RS-PR-006 already flags bad networks
        namespace = network.split(":", 1)[0]
        for field in ("payTo", "asset"):
            value = e.get(field)
            if not isinstance(value, str):
                continue
            looks_evm = bool(_EVM_ADDRESS_RE.match(value))
            if namespace == "eip155" and not looks_evm:
                problems.append(
                    f"accepts[{i}].{field}={value!r} is not an EVM address but network is {network}"
                )
            elif namespace in ("solana", "xrpl") and looks_evm:
                # A 0x EVM address on a non-EVM rail is an unambiguous mismatch: Solana
                # uses base58 accounts, XRPL uses classic r-addresses. This is safe to
                # gate without a per-chain address validator (which we do not have).
                problems.append(
                    f"accepts[{i}].{field}={value!r} is an EVM address but network is {network}"
                )
    if problems:
        return Status.FAIL, "; ".join(problems)
    return Status.PASS, ""


@register(
    "RS-PR-014",
    "amount is strictly positive",
    Severity.MAJOR,
    f"{_CORE} §5.1.2 + testcase N5",
)
def pr_014(s: ProbeSession) -> tuple[Status, str]:
    """Evaluate RS-PR-014: amount is strictly positive."""
    accepts = _accepts_raw(s)
    if not accepts:
        return Status.SKIP, "no accepts entries to inspect"
    bad = []
    for i, e in enumerate(accepts):
        amount = e.get("amount")
        if not isinstance(amount, str):
            continue  # RS-PR-007 handles non-string amounts
        try:
            if int(amount) <= 0:
                bad.append(f"accepts[{i}].amount={amount!r} is not > 0")
        except ValueError:
            continue  # RS-PR-007 handles non-integer amounts
    if bad:
        return Status.FAIL, "; ".join(bad) + " — a zero/negative price is a logic hole"
    return Status.PASS, ""


@register(
    "RS-PR-015",
    "jp402 tax breakdown (if present) is structurally consistent",
    Severity.MINOR,
    "jp402-registry (community JP-rail extension)",
)
def pr_015(s: ProbeSession) -> tuple[Status, str]:
    # Opt-in JP-rail check: only fires when the live 402 advertises the community
    # `jp402` extension; otherwise SKIP (never gates a non-JP endpoint). MINOR, so a
    # malformed tax block can't flip the verdict. Confirmed against real fixtures
    # (2026-06-29): the live 402 carries `jp402.tax` (excl_jpyc/vat_jpyc/rate) on the
    # accepts entry — the qualified-invoice/registrationNumber lives in the seller's
    # OpenAPI doc instead (see jp402.find_invoice_blocks / validate_invoice).
    """Evaluate RS-PR-015: jp402 tax breakdown (if present) is structurally consistent."""
    if s.first.raw is None:
        return Status.SKIP, "no decoded PaymentRequired payload"
    found = find_jp402_accept(s.first.raw)
    if found is not None:
        entry, block = found
        amount: object | None = entry.get("amount")
    else:
        ext_block = find_jp402(s.first.raw)
        if ext_block is None:
            return Status.SKIP, "no jp402 extension advertised (opt-in JP-rail check)"
        block = ext_block
        amount = None
    tax = block.get("tax")
    if not isinstance(tax, dict):
        return (
            Status.SKIP,
            "jp402 present but carries no tax block (invoice lives in the OpenAPI doc)",
        )
    problems = validate_tax(tax, amount)
    if problems:
        return Status.FAIL, "; ".join(problems)
    return Status.PASS, "jp402 tax breakdown is structurally consistent"


@register(
    "RS-PR-016",
    "jp402 OpenAPI invoice (when jp402 is advertised) is structurally valid",
    Severity.MINOR,
    "jp402-registry (community JP-rail extension)",
)
def pr_016(s: ProbeSession) -> tuple[Status, str]:
    # The qualified-invoice metadata (registrationNumber) lives in the seller's
    # OpenAPI doc, not on the live 402. The runner fetched `/openapi.json` only when
    # the 402 advertised `jp402`; here we validate the `x-jp402.invoice` block(s).
    # Opt-in + MINOR: never gates a non-JP endpoint, and an unreachable/absent doc is
    # a SKIP (we couldn't check) — only a present-but-malformed invoice FAILs.
    """Evaluate RS-PR-016: jp402 OpenAPI invoice (when jp402 is advertised) is structurally valid."""
    if s.first.raw is None or find_jp402(s.first.raw) is None:
        return Status.SKIP, "no jp402 advertised (opt-in JP-rail check)"
    if s.openapi is None:
        return (
            Status.SKIP,
            "jp402 advertised but /openapi.json was unreachable or not a JSON object",
        )
    invoices = find_invoice_blocks(s.openapi)
    if not invoices:
        return Status.SKIP, "OpenAPI doc carries no x-jp402.invoice block"
    problems: list[str] = []
    for invoice in invoices:
        problems.extend(validate_invoice(invoice))
    if problems:
        return Status.FAIL, "; ".join(problems)
    return Status.PASS, f"{len(invoices)} x-jp402 invoice block(s) structurally valid"


@register(
    "RS-PR-017",
    "accepts scheme is a known payment scheme",
    Severity.MAJOR,
    f"{_CORE} Document Scope + §6",
)
def pr_017(s: ProbeSession) -> tuple[Status, str]:
    """Evaluate RS-PR-017: accepts scheme is a known payment scheme."""
    accepts = _accepts_raw(s)
    if not accepts:
        return Status.SKIP, "no accepts entries to inspect"
    bad = []
    for i, e in enumerate(accepts):
        scheme = e.get("scheme")
        if not isinstance(scheme, str):
            continue  # RS-PR-005 handles a missing/non-string scheme
        if scheme not in _KNOWN_SCHEMES:
            bad.append(f"accepts[{i}].scheme={scheme!r}")
    if bad:
        return Status.FAIL, (
            "unknown payment scheme(s): "
            + ", ".join(bad)
            + f" — not one of {sorted(_KNOWN_SCHEMES)}; no conformant client can pay these"
        )
    return Status.PASS, ""


@register(
    "RS-PR-018",
    "no contradictory accepts entries for the same rail+asset",
    Severity.MAJOR,
    f"{_CORE} §5.1.2",
)
def pr_018(s: ProbeSession) -> tuple[Status, str]:
    """Evaluate RS-PR-018: no contradictory accepts entries for the same rail+asset."""
    accepts = _accepts_raw(s)
    if not accepts:
        return Status.SKIP, "no accepts entries to inspect"
    # Offering the same asset on the same rail (scheme+network) at two different
    # (payTo, amount) pairs is a genuine ambiguity: a client cannot tell which
    # recipient or price is real. Two entries that differ only by asset (pay in
    # USDC *or* DAI) are a legitimate choice, not a contradiction — so the group
    # key includes asset and only (payTo, amount) variance within a group fails.
    groups: dict[tuple[object, object, object], set[tuple[object, object]]] = {}
    for e in accepts:
        key = (_hkey(e.get("scheme")), _hkey(e.get("network")), _hkey(e.get("asset")))
        groups.setdefault(key, set()).add((_hkey(e.get("payTo")), _hkey(e.get("amount"))))
    problems = []
    for (scheme, network, asset), variants in groups.items():
        if len(variants) > 1:
            problems.append(
                f"scheme={scheme!r} network={network!r} asset={asset!r} offered with "
                f"{len(variants)} different (payTo, amount) combinations"
            )
    if problems:
        return Status.FAIL, "; ".join(problems) + " — ambiguous which payment is the real one"
    return Status.PASS, ""


@register(
    "RS-PR-019",
    "accepts extra fields match the entry's scheme",
    Severity.MINOR,
    "scheme_exact_evm.md + scheme_upto_svm.md",
)
def pr_019(s: ProbeSession) -> tuple[Status, str]:
    """Evaluate RS-PR-019: accepts extra fields match the entry's scheme."""
    if _x402_version(s) == 1:
        return Status.SKIP, _V1_SKIP
    accepts = _accepts_raw(s)
    if not accepts:
        return Status.SKIP, "no accepts entries to inspect"
    problems = []
    for i, e in enumerate(accepts):
        raw_extra = e.get("extra")
        if not isinstance(raw_extra, dict):
            continue
        # The protocol-reserved keys belong to no scheme's vocabulary, so they can
        # never be a mismatch in either direction (CORE §6.1).
        keys = set(raw_extra) - _RESERVED_EXTRA_KEYS
        scheme = e.get("scheme")
        if scheme == "exact":
            leaked = sorted(keys & _UPTO_EXTRA_KEYS)
            if leaked:
                problems.append(
                    f"accepts[{i}] scheme=exact carries upto-only extra field(s): "
                    + ", ".join(leaked)
                )
        elif scheme == "upto":
            leaked = sorted(keys & _EXACT_EXTRA_KEYS)
            if leaked:
                problems.append(
                    f"accepts[{i}] scheme=upto carries exact-only extra field(s): "
                    + ", ".join(leaked)
                )
    if problems:
        return Status.FAIL, "; ".join(problems) + " — extra does not match the declared scheme"
    return Status.PASS, ""


@register(
    "RS-PR-020",
    "accepts entries carry no fields outside the v2 schema",
    Severity.MINOR,
    f"{_CORE} §5.1.2",
)
def pr_020(s: ProbeSession) -> tuple[Status, str]:
    """Evaluate RS-PR-020: accepts entries carry no fields outside the v2 schema."""
    if _x402_version(s) == 1:
        return Status.SKIP, _V1_SKIP
    accepts = _accepts_raw(s)
    if not accepts:
        return Status.SKIP, "no accepts entries to inspect"
    problems = []
    for i, e in enumerate(accepts):
        unknown = sorted(set(e) - _KNOWN_ACCEPT_FIELDS)
        if unknown:
            problems.append(f"accepts[{i}] has non-v2 field(s): " + ", ".join(unknown))
    if problems:
        return Status.FAIL, (
            "; ".join(problems)
            + " — outside the §5.1.2 PaymentRequirements set; a conformant client ignores "
            "them, so any payment-relevant data placed here is silently dropped"
        )
    return Status.PASS, ""


@register(
    "RS-PR-021",
    "challenge is standard JSON (no NaN/Infinity literals)",
    Severity.MAJOR,
    "RFC 8259 §6 + " + _CORE + " §5.1.1",
)
def pr_021(s: ProbeSession) -> tuple[Status, str]:
    """Evaluate RS-PR-021: challenge is standard JSON (no NaN/Infinity literals)."""
    if s.first.raw is None:
        return Status.SKIP, "no decoded PaymentRequired payload"
    literals = s.first.nonstandard_json_literals
    if not literals:
        return Status.PASS, ""
    return Status.FAIL, (
        f"challenge contains the non-standard JSON literal(s) {', '.join(literals)} — "
        "RFC 8259 defines no such values. Python's decoder accepts them, Go's and "
        "the JSON specification's do not, so this challenge is unreadable to part of "
        "your clients while looking fine to the rest"
    )


@register(
    "RS-PR-022",
    "challenge has no duplicate object keys",
    Severity.MAJOR,
    "RFC 8259 §4 + " + _CORE + " §5.1.1",
)
def pr_022(s: ProbeSession) -> tuple[Status, str]:
    """Evaluate RS-PR-022: challenge has no duplicate object keys."""
    if s.first.raw is None:
        return Status.SKIP, "no decoded PaymentRequired payload"
    duplicates = s.first.duplicate_json_keys
    if not duplicates:
        return Status.PASS, ""
    return Status.FAIL, (
        f"challenge repeats the key(s) {', '.join(repr(k) for k in duplicates)}. "
        "RFC 8259 permits this but leaves the meaning to the parser: last-wins, "
        "first-wins and outright rejection are all in use. On a payment challenge "
        "that is a field whose value depends on which client reads it"
    )


# --- builder-code (specs/extensions/builder_code.md) ------------------------------
#
# The extension was format-only when this suite last reviewed it: codes had to
# match ^[a-z0-9_]{1,32}$ and that was the whole contract, which is why the
# support matrix listed builder-code as passive-only. x402#3027 and #2994 gave it
# real structure — per-party service-code reservations that cannot be crowded out,
# and an explicit rule for what the client may echo — so the server-declared half
# is now checkable from the challenge alone.

#: specs/extensions/builder_code.md — all of `a`, `w` and each entry in `s`.
_BUILDER_CODE_PATTERN = re.compile(r"^[a-z0-9_]{1,32}$")

#: MAX_SERVER_SERVICE_CODES. The reservations are per party (client 5, server 5,
#: facilitator 1, total 11) precisely so no party can crowd out another; a server
#: over its own budget is what gets truncated downstream.
_MAX_SERVER_SERVICE_CODES = 5


def _builder_code_info(s: ProbeSession) -> dict[str, object] | None:
    """Return the server-declared `builder-code` info object, if the challenge has one."""
    if s.first.raw is None:
        return None
    extensions = s.first.raw.get("extensions")
    if not isinstance(extensions, dict):
        return None
    entry = extensions.get("builder-code")
    if not isinstance(entry, dict):
        return None
    info = entry.get("info")
    return info if isinstance(info, dict) else None


@register(
    "RS-PR-023",
    "declared builder-code app code is well-formed",
    Severity.MINOR,
    "extensions/builder_code.md §Builder Code Validation",
)
def pr_023(s: ProbeSession) -> tuple[Status, str]:
    """Evaluate RS-PR-023: declared builder-code app code is well-formed."""
    info = _builder_code_info(s)
    if info is None:
        return Status.SKIP, "no builder-code extension declared"
    if "a" not in info:
        # `a` is the application's own identifier; a builder-code block without it
        # attributes nothing. Not fatal to payment, hence MINOR.
        return Status.PASS, "builder-code declared without an app code"
    app_code = info["a"]
    if not isinstance(app_code, str) or not _BUILDER_CODE_PATTERN.match(app_code):
        return Status.FAIL, (
            f"builder-code app code {app_code!r} does not match ^[a-z0-9_]{{1,32}}$ — "
            "the facilitator must reject invalid codes at construction time, so "
            "attribution silently drops"
        )
    return Status.PASS, ""


@register(
    "RS-PR-024",
    "declared builder-code service codes stay within the server reservation",
    Severity.MINOR,
    "extensions/builder_code.md §Builder Code Fields + x402#3027",
)
def pr_024(s: ProbeSession) -> tuple[Status, str]:
    """Evaluate RS-PR-024: declared builder-code service codes stay within the server reservation."""
    info = _builder_code_info(s)
    if info is None:
        return Status.SKIP, "no builder-code extension declared"
    if "s" not in info:
        return Status.PASS, "no server service codes declared"
    declared = info["s"]
    # The spec accepts a bare string or an array on either side; a scalar merges
    # as a single-element array against the other party's array.
    codes = [declared] if isinstance(declared, str) else declared
    if not isinstance(codes, list):
        return (
            Status.FAIL,
            f"builder-code `s` must be a string or an array, got {type(declared).__name__}",
        )
    problems = [
        repr(c) for c in codes if not (isinstance(c, str) and _BUILDER_CODE_PATTERN.match(c))
    ]
    if problems:
        return Status.FAIL, (
            f"builder-code service code(s) {', '.join(problems[:4])} do not match "
            "^[a-z0-9_]{1,32}$"
        )
    if len(codes) > _MAX_SERVER_SERVICE_CODES:
        return Status.FAIL, (
            f"{len(codes)} server service codes declared, over the "
            f"MAX_SERVER_SERVICE_CODES reservation of {_MAX_SERVER_SERVICE_CODES}. "
            "The per-party budgets exist so no participant can crowd out another; "
            "entries past the reservation are rejected or truncated downstream, so "
            "the attribution declared here is not the attribution that settles"
        )
    return Status.PASS, f"{len(codes)} server service code(s), within reservation"


# --- payment flow models (CORE §6.1, x402#3053/#3088/#3115) ------------------------
#
# Schemes differ not only in how a payment is formed but in *when* settlement
# happens relative to the resource running. §6.1 names three orderings and makes
# `extra.paymentFlow` a protocol-reserved key so a client can tell them apart
# without knowing the mechanism:
#
#   authorization  verify -> resource -> settle -> respond   (funds move after)
#   upfront        settle -> resource -> respond             (funds committed first)
#   escrow         settle -> resource -> settle -> respond   (deposit, then charge)
#
# The difference is the payer's money. Under `authorization` a client that never
# gets its resource has authorized nothing that moved; under the other two the
# commitment already happened. That is what these checks are about.


@register(
    "RS-PR-025",
    "declared paymentFlow is one the protocol defines",
    Severity.MAJOR,
    f"{_CORE} §6.1",
)
def pr_025(s: ProbeSession) -> tuple[Status, str]:
    """Evaluate RS-PR-025: declared paymentFlow is one the protocol defines."""
    if _x402_version(s) == 1:
        return Status.SKIP, _V1_SKIP
    accepts = _accepts_raw(s)
    if not accepts:
        return Status.SKIP, "no accepts entries to inspect"
    declared = 0
    problems = []
    for i, e in enumerate(accepts):
        raw_extra = e.get("extra")
        if not isinstance(raw_extra, dict) or "paymentFlow" not in raw_extra:
            continue
        declared += 1
        flow = raw_extra["paymentFlow"]
        if not isinstance(flow, str) or flow not in _PAYMENT_FLOWS:
            problems.append(f"accepts[{i}].extra.paymentFlow={flow!r}")
    if declared == 0:
        return Status.SKIP, "no entry declares extra.paymentFlow"
    if problems:
        return Status.FAIL, (
            "; ".join(problems) + " — not one of "
            f"{', '.join(sorted(_PAYMENT_FLOWS))}. §6.1 says a client MUST NOT construct "
            "a payment for a paymentFlow it does not recognize and SHOULD skip the entry, "
            "so an invented value makes this entry unpayable by every conformant client"
        )
    return Status.PASS, f"{declared} entry/entries declare a defined paymentFlow"


@register(
    "RS-PR-026",
    "a flow that commits funds before the resource runs says so",
    Severity.MINOR,
    f"{_CORE} §6.1 vs scheme_upto_svm.md §PaymentRequirements",
)
def pr_026(s: ProbeSession) -> tuple[Status, str]:
    """Evaluate RS-PR-026: a flow that commits funds before the resource runs says so.

    Advisory, and deliberately so — upstream currently says both things. CORE §6.1:
    "When the resolved payment flow is not `authorization`, `PaymentRequired`
    `accepts[].extra.paymentFlow` MUST be present so clients can reason about
    pre-handler fund commitment without scheme-specific knowledge."
    `scheme_upto_svm.md` §PaymentRequirements, on the same field: "Only supported
    value is `escrow`; omit to use that default."

    An endpoint following the scheme binding literally omits the field and is
    correct by that document while violating the core one. Gating on it would
    fail an implementation for picking the wrong half of a contradiction, so this
    reports and never gates. Revisit when upstream reconciles the two.
    """
    if _x402_version(s) == 1:
        return Status.SKIP, _V1_SKIP
    accepts = _accepts_raw(s)
    if not accepts:
        return Status.SKIP, "no accepts entries to inspect"
    candidates = 0
    problems = []
    for i, e in enumerate(accepts):
        raw_extra = e.get("extra")
        if not isinstance(raw_extra, dict):
            continue
        # Only entries whose extra actually carries escrow/upfront machinery are
        # graded. Inferring the resolved flow for an arbitrary mechanism needs
        # knowledge this suite does not have, and guessing would turn a silent
        # omission into a false accusation.
        signals = sorted(set(raw_extra) & _ESCROW_EXTRA_SIGNALS)
        if not signals:
            continue
        candidates += 1
        if "paymentFlow" not in raw_extra:
            problems.append(f"accepts[{i}].extra has {', '.join(signals)} but no paymentFlow")
    if candidates == 0:
        return Status.SKIP, "no entry carries pre-handler settlement fields"
    if problems:
        return Status.PASS, (
            "advisory: "
            + "; ".join(problems)
            + " — CORE §6.1 wants paymentFlow present whenever the resolved flow is not "
            "`authorization`, so a client can see its funds are committed before the "
            "resource runs. scheme_upto_svm.md permits omitting it and defaulting to "
            "`escrow`, so this is not graded; declaring it explicitly costs nothing and "
            "removes the ambiguity"
        )
    return Status.PASS, f"{candidates} pre-handler entry/entries declare their flow"
