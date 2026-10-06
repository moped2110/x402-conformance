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

#: Scheme-private `extra` vocabularies per binding, keyed on (scheme, CAIP-2
#: namespace) and taken from each binding's PaymentRequirements table at upstream
#: main@cb0ec5b. The 2026-10 review replaced the old two-set model (`exact` =
#: EVM domain fields, `upto` = SVM channel fields), which failed spec-conformant
#: exact SVM, exact Hedera, exact Starknet and EVM upto entries: the same key
#: (`feePayer`, `name`) is legal under one binding and foreign under another.
#: The reserved keys above are in none of these sets and never graded.
_BINDING_EXTRA_KEYS: dict[tuple[str, str], frozenset[str]] = {
    ("exact", "eip155"): frozenset({"name", "version"}),
    ("exact", "solana"): frozenset({"feePayer", "recentBlockhash", "lastValidBlockHeight", "memo"}),
    ("exact", "hedera"): frozenset({"feePayer", "executors"}),
    ("exact", "starknet"): frozenset({"feePayer"}),
    ("exact", "lnbtc"): frozenset(
        {"invoice", "requestHash", "requestBindingProfile", "requestBindingParams"}
    ),
    ("exact", "cardano"): frozenset(
        {
            "confirmationPolicy",
            "datum",
            "deployment",
            "inputCommitment",
            "referenceKey",
            "referenceSignature",
            "blockchainIdentifier",
            "areFeesSponsored",
            "terms",
            "script",
            "scriptHash",
            "parameters",
        }
    ),
    ("upto", "eip155"): frozenset({"name", "version", "facilitatorAddress"}),
    ("upto", "solana"): frozenset(
        {
            "feePayer",
            "receiverAuthorizer",
            "withdrawDelay",
            "tokenProgram",
            "memo",
            "recentBlockhash",
            "lastValidBlockHeight",
            "recentSlot",
            "validAfter",
        }
    ),
    ("batch-settlement", "eip155"): frozenset(
        {
            "receiverAuthorizer",
            "withdrawDelay",
            "name",
            "version",
            "minDeposit",
            "channelState",
            "voucherState",
        }
    ),
    ("batch-settlement", "solana"): frozenset(
        {
            "feePayer",
            "receiverAuthorizer",
            "voucherSigner",
            "operator",
            "withdrawDelay",
            "tokenProgram",
            "memo",
            "recentBlockhash",
            "recentSlot",
            "minDeposit",
            "maxIdleSecs",
            "channelState",
            "voucherState",
        }
    ),
    ("auth-capture", "eip155"): frozenset(
        {
            "name",
            "version",
            "authCaptureEscrow",
            "captureAuthorizer",
            "receiverAuthorizer",
            "policy",
            "captureDeadline",
            "refundDeadline",
            "feeRecipient",
            "minFeeBps",
            "maxFeeBps",
            "captureMode",
            "operatorType",
            "operators",
        }
    ),
}

#: Every key some binding above defines. A key outside this union is not graded:
#: it may belong to a binding this suite has no vocabulary for, and RS-PR-019 only
#: speaks to keys it can attribute to a *different* binding.
_ALL_BINDING_EXTRA_KEYS = frozenset().union(*_BINDING_EXTRA_KEYS.values())


def _binding(entry: dict[str, object]) -> tuple[str, str] | None:
    """Return (scheme, CAIP-2 namespace) for an accepts entry, or None if either is unreadable."""
    scheme = entry.get("scheme")
    network = entry.get("network")
    if not isinstance(scheme, str) or not isinstance(network, str) or ":" not in network:
        return None
    return scheme, network.split(":", 1)[0]


#: The payment flow models defined in CORE §6.1. `authorization` verifies before
#: the resource runs and settles after; `upfront` and `escrow` commit funds
#: *before* it runs.
_PAYMENT_FLOWS = frozenset({"authorization", "upfront", "escrow"})

#: Flows that bind the payer's money before the resource executes. The spec
#: requires these to be declared explicitly so a client can see the commitment
#: coming without knowing the mechanism.
_PRE_HANDLER_FLOWS = frozenset({"upfront", "escrow"})

#: Bindings whose flow, when `extra.paymentFlow` is omitted, resolves to a
#: pre-handler flow by the binding's own default: SVM `upto` ("omit to use that
#: default", scheme_upto_svm.md) and `auth-capture` (escrow by default,
#: scheme_auth_capture.md v1.1). The namespace "*" matches any network.
_PRE_HANDLER_DEFAULT_BINDINGS = frozenset({("upto", "solana"), ("auth-capture", "*")})

#: Bindings whose flow is `authorization` (or unspecified) even though their
#: `extra` carries channel machinery: SVM batch-settlement ("if present, MUST be
#: authorization"), EVM upto, and EVM batch-settlement, whose binding does not
#: specify a flow. RS-PR-026 does not treat their channel fields as an escrow hint.
_NOT_PRE_HANDLER_BINDINGS = frozenset(
    {("batch-settlement", "solana"), ("upto", "eip155"), ("batch-settlement", "eip155")}
)

#: For a binding this suite has no flow knowledge of, `extra` fields that only
#: exist because a mechanism holds funds before the resource runs. `autoCapture`
#: was a signal until auth-capture v1.1 removed it (and now requires rejecting
#: `autoCapture: true`, see RS-PR-027).
_ESCROW_EXTRA_SIGNALS = frozenset({"withdrawDelay", "receiverAuthorizer"})


def _binding_in(binding: tuple[str, str] | None, bindings: frozenset[tuple[str, str]]) -> bool:
    """Whether a binding matches a set that may use "*" as a namespace wildcard."""
    if binding is None:
        return False
    return binding in bindings or (binding[0], "*") in bindings


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
    # The protocol-reserved extra keys are part of the key too: since x402#3145 the
    # same asset may be offered once per paymentFlow / assetTransferMethod (e.g. an
    # `upfront` entry at one price next to an `authorization` entry at another),
    # and those are distinct offers, not a contradiction.
    groups: dict[tuple[object, ...], set[tuple[object, object]]] = {}
    for e in accepts:
        raw_extra = e.get("extra")
        extra = raw_extra if isinstance(raw_extra, dict) else {}
        key = (
            _hkey(e.get("scheme")),
            _hkey(e.get("network")),
            _hkey(e.get("asset")),
            *(_hkey(extra.get(k)) for k in sorted(_RESERVED_EXTRA_KEYS)),
        )
        groups.setdefault(key, set()).add((_hkey(e.get("payTo")), _hkey(e.get("amount"))))
    problems = []
    for (scheme, network, asset, *reserved), variants in groups.items():
        if len(variants) > 1:
            qualifier = "".join(
                f" {k}={v!r}"
                for k, v in zip(sorted(_RESERVED_EXTRA_KEYS), reserved, strict=True)
                if v is not None
            )
            problems.append(
                f"scheme={scheme!r} network={network!r} asset={asset!r}{qualifier} offered "
                f"with {len(variants)} different (payTo, amount) combinations"
            )
    if problems:
        return Status.FAIL, "; ".join(problems) + " — ambiguous which payment is the real one"
    return Status.PASS, ""


@register(
    "RS-PR-019",
    "accepts extra fields match the entry's scheme binding",
    Severity.MINOR,
    "scheme_<scheme>_<family>.md PaymentRequirements tables",
)
def pr_019(s: ProbeSession) -> tuple[Status, str]:
    """Evaluate RS-PR-019: accepts extra fields match the entry's (scheme, network family).

    A key is a mismatch only when this suite knows the entry's binding, the key is
    not in that binding's vocabulary, and the key *is* in another binding's
    vocabulary, i.e. it was most likely copied from the wrong scheme or chain.
    Bindings without a vocabulary here (Aptos, Stellar, Sui, …) are not graded, and
    unknown keys are left to the binding's own validation.
    """
    if _x402_version(s) == 1:
        return Status.SKIP, _V1_SKIP
    accepts = _accepts_raw(s)
    if not accepts:
        return Status.SKIP, "no accepts entries to inspect"
    graded = 0
    problems = []
    for i, e in enumerate(accepts):
        raw_extra = e.get("extra")
        binding = _binding(e)
        if not isinstance(raw_extra, dict) or binding not in _BINDING_EXTRA_KEYS:
            continue
        assert binding is not None  # narrowed by the membership test above
        graded += 1
        own = _BINDING_EXTRA_KEYS[binding]
        # The protocol-reserved keys belong to no binding's vocabulary, so they can
        # never be a mismatch (CORE §6.1).
        foreign = sorted((set(raw_extra) - _RESERVED_EXTRA_KEYS - own) & _ALL_BINDING_EXTRA_KEYS)
        if foreign:
            problems.append(
                f"accepts[{i}] {binding[0]} on {binding[1]} carries extra field(s) from "
                "another binding: " + ", ".join(foreign)
            )
    if graded == 0:
        return Status.SKIP, "no entry with extra on a binding this suite has a vocabulary for"
    if problems:
        return Status.FAIL, "; ".join(problems) + " — extra does not match the declared binding"
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
    f"{_CORE} §6.1 vs scheme_upto_svm.md / scheme_auth_capture.md",
)
def pr_026(s: ProbeSession) -> tuple[Status, str]:
    """Evaluate RS-PR-026: a flow that commits funds before the resource runs says so.

    Advisory, and deliberately so — upstream currently says both things. CORE §6.1:
    "When the resolved payment flow is not `authorization`, `PaymentRequired`
    `accepts[].extra.paymentFlow` MUST be present so clients can reason about
    pre-handler fund commitment without scheme-specific knowledge."
    `scheme_upto_svm.md` §PaymentRequirements, on the same field: "Only supported
    value is `escrow`; omit to use that default." auth-capture v1.1 has the same
    escrow default.

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
        extra = raw_extra if isinstance(raw_extra, dict) else {}
        binding = _binding(e)
        # Scheme-aware since the 2026-10 review. A binding whose default flow is
        # escrow is a candidate whether or not its extra looks like escrow; a binding
        # that is authorization (SVM batch-settlement, EVM upto) or unspecified (EVM
        # batch-settlement) never is, even though it carries channel fields; for the
        # rest, the generic signals are the only hint. Guessing beyond that would
        # turn a silent omission into a false accusation.
        if _binding_in(binding, _NOT_PRE_HANDLER_BINDINGS):
            continue
        if _binding_in(binding, _PRE_HANDLER_DEFAULT_BINDINGS):
            hint = f"{binding[0]} on {binding[1]} defaults to escrow" if binding else ""
        else:
            signals = sorted(set(extra) & _ESCROW_EXTRA_SIGNALS)
            if not signals:
                continue
            hint = f"extra has {', '.join(signals)}"
        candidates += 1
        if "paymentFlow" not in extra:
            problems.append(f"accepts[{i}]: {hint} but declares no paymentFlow")
    if candidates == 0:
        return Status.SKIP, "no entry resolves to a pre-handler flow this suite can infer"
    if problems:
        return Status.PASS, (
            "advisory: "
            + "; ".join(problems)
            + " — CORE §6.1 wants paymentFlow present whenever the resolved flow is not "
            "`authorization`, so a client can see its funds are committed before the "
            "resource runs. scheme_upto_svm.md and scheme_auth_capture.md permit omitting "
            "it and defaulting to `escrow`, so this is not graded; declaring it explicitly "
            "costs nothing and removes the ambiguity"
        )
    return Status.PASS, f"{candidates} pre-handler entry/entries declare their flow"


def _resolved_flow(entry: dict[str, object]) -> object:
    """Return an entry's declared paymentFlow, defaulting to the protocol's `authorization`."""
    raw_extra = entry.get("extra")
    extra = raw_extra if isinstance(raw_extra, dict) else {}
    return extra.get("paymentFlow", "authorization")


def _flow_problems(entry: dict[str, object], binding: tuple[str, str] | None) -> list[str]:
    """Return the binding-specific paymentFlow MUST violations for one accepts entry."""
    raw_extra = entry.get("extra")
    extra = raw_extra if isinstance(raw_extra, dict) else {}
    present = "paymentFlow" in extra
    flow = extra.get("paymentFlow")
    if present and flow not in _PAYMENT_FLOWS:
        return []  # an undefined value is RS-PR-025's finding, not a binding mismatch
    if binding is None:
        return []
    scheme, family = binding
    problems: list[str] = []
    if scheme == "upto" and flow == "upfront":
        problems.append("upto MUST NOT use paymentFlow 'upfront' (scheme_upto.md)")
    if scheme == "upto" and family == "solana" and present and flow != "escrow":
        problems.append(f"SVM upto supports only 'escrow', got {flow!r} (scheme_upto_svm.md)")
    if (scheme, family) == ("exact", "lnbtc") and flow != "upfront":
        got = repr(flow) if present else "no paymentFlow"
        problems.append(
            f"exact on lnbtc MUST declare paymentFlow 'upfront', got {got} (scheme_exact_lnbtc.md)"
        )
    if (
        (scheme, family)
        in {
            ("exact", "starknet"),
            ("exact", "cardano"),
            ("batch-settlement", "solana"),
        }
        and present
        and flow != "authorization"
    ):
        problems.append(
            f"{scheme} on {family} is always 'authorization' when paymentFlow is present, "
            f"got {flow!r}"
        )
    if scheme == "auth-capture":
        if present and flow not in ("escrow", "authorization"):
            problems.append(f"auth-capture allows 'escrow' or 'authorization', got {flow!r}")
        if extra.get("autoCapture") is True:
            problems.append(
                "auth-capture v1.1 removed autoCapture; `autoCapture: true` MUST be rejected "
                "(invalid_auth_capture_evm_unsupported_payment_flow)"
            )
        if flow == "authorization" and "captureMode" in extra:
            problems.append("captureMode MUST NOT be set when paymentFlow is 'authorization'")
    return problems


#: Bindings RS-PR-027 grades even without a declared flow, because they carry a
#: MUST that an omission can violate or a field (autoCapture/captureMode) it reads.
_FLOW_CONSTRAINED = frozenset(
    {
        ("upto", "*"),
        ("exact", "lnbtc"),
        ("exact", "starknet"),
        ("exact", "cardano"),
        ("batch-settlement", "solana"),
        ("auth-capture", "*"),
    }
)


@register(
    "RS-PR-027",
    "declared paymentFlow is one the entry's scheme binding allows",
    Severity.MAJOR,
    f"{_CORE} §6.1 + scheme_exact.md, scheme_upto*.md, scheme_exact_lnbtc.md, "
    "scheme_exact_starknet.md, scheme_batch_settlement_svm.md, scheme_auth_capture_evm.md",
)
def pr_027(s: ProbeSession) -> tuple[Status, str]:
    """Evaluate RS-PR-027: paymentFlow per binding (x402#3145, auth-capture v1.1).

    MUST rules fail: `upto` is never `upfront`; Lightning `exact` is always
    `upfront` and must say so; Starknet and Cardano `exact` and SVM
    batch-settlement are `authorization` when the field is present; SVM `upto` is
    `escrow`; auth-capture is `escrow` or `authorization`, rejects
    `autoCapture: true`, and has no `captureMode` under `authorization`. The
    SHOULD (scheme_exact.md: prefer `authorization` when both are offered) is
    advisory: an `upfront` exact entry with no `authorization` sibling for the
    same network and asset is reported, never failed.
    """
    if _x402_version(s) == 1:
        return Status.SKIP, _V1_SKIP
    accepts = _accepts_raw(s)
    if not accepts:
        return Status.SKIP, "no accepts entries to inspect"
    graded = 0
    problems: list[str] = []
    advisories: list[str] = []
    for i, e in enumerate(accepts):
        binding = _binding(e)
        raw_extra = e.get("extra")
        extra = raw_extra if isinstance(raw_extra, dict) else {}
        upfront_exact = (
            binding is not None
            and binding[0] == "exact"
            and (extra.get("paymentFlow") == "upfront")
        )
        if not _binding_in(binding, _FLOW_CONSTRAINED) and not upfront_exact:
            continue
        graded += 1
        problems.extend(f"accepts[{i}]: {p}" for p in _flow_problems(e, binding))
        if upfront_exact and binding != ("exact", "lnbtc"):
            siblings = [
                o
                for o in accepts
                if o is not e
                and o.get("scheme") == "exact"
                and o.get("network") == e.get("network")
                and o.get("asset") == e.get("asset")
                and _resolved_flow(o) == "authorization"
            ]
            if not siblings:
                advisories.append(
                    f"accepts[{i}] offers exact as 'upfront' only — scheme_exact.md says "
                    "`authorization` SHOULD be preferred and defines no refund for upfront"
                )
    if graded == 0:
        return Status.SKIP, "no entry on a binding with paymentFlow constraints"
    if problems:
        return Status.FAIL, "; ".join(problems)
    if advisories:
        return Status.PASS, "advisory: " + "; ".join(advisories)
    return Status.PASS, f"{graded} flow-constrained entry/entries match their binding"
