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


def _accepts_raw(s: ProbeSession) -> list[dict[str, object]] | None:
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
            elif namespace == "solana" and looks_evm:
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
