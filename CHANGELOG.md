# Changelog

All notable changes to x402-conformance are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- **RS-NEG-011** (`check --active`): a payment whose `accepted` claims a scheme/network
  the endpoint never offered must be rejected (`invalid_scheme`/`invalid_network`), not
  served. MAJOR.
- **RS-NEG-012** (`check --active`): a payment with a top-level `x402Version` != 2
  (here 99) must be rejected cleanly (`invalid_x402_version`), not mis-parsed. MAJOR.
- **RS-SEC-005** (`check --active`): oversized `PAYMENT-SIGNATURE` header (~1 MB) must
  be rejected cleanly (a 4xx) — no 5xx crash, no hang, resource not served. Basic
  header-path DoS hygiene. MINOR.
- **RS-SEC-007** (`check --active`): control/Unicode characters embedded in a payload
  field (NUL, RTL-override, BEL, non-ASCII) must be rejected cleanly, not 5xx-crash a
  naive parser. Structurally valid base64+JSON; the mangled `from` no longer recovers
  from the signature. MINOR. (RS-SEC-006 header-smuggling deferred — needs a
  second-header active primitive + a sharper precedence assertion.)
- **`check --fix`**: a developer-facing report instead of the full table — failures
  only, grouped by severity (CRITICAL/MAJOR/MINOR), each with what's wrong, a
  remediation hint ("how to fix"), and the spec reference. Turns a pass/fail run into
  an actionable punch-list for the endpoint owner. (`report.to_developer_report`.)
- **RS-PR-015** (`check`): opt-in structural check for the community `x-jp402`
  invoice extension — validates the qualified-invoice registration number
  (`^T[0-9]{13}$`, 適格請求書発行事業者登録番号) and boolean flags. SKIPs unless an
  endpoint advertises `x-jp402`, MINOR severity so it never gates a non-JP endpoint.
  (Community extension, not x402-core; live-402 placement + the separate `jp402.tax`
  breakdown are pending a real fixture.)
- **RS-NEG-015** (`check --active`) & **FA-VER-003** (`facilitator`): asset-is-an-EOA
  rejection. A payment whose `asset` points at a wallet (no contract code) must be
  rejected — a `transferWithAuthorization` call to an EOA never reverts, so
  settlement would be a silent no-op. Mirrors the upstream `asset_not_deployed_contract`
  guard (x402#2554), now added to the known error-code registry.
- **RS-SEC-011** (`check --active`): extreme/near-2²⁵⁶ amount robustness — the
  endpoint must reject a uint256-max amount cleanly without a 5xx crash.
- **`--resource-marker`** for `check --active`: pass a unique string from the
  protected resource; a rejected response whose body still contains it is flagged
  as a content leak (RS-SEC-009 on the rejection path).
- **`report.schema.json`**: a versioned JSON Schema for the `--json` report
  output, with a `reportVersion` field; CI validates the output against it.

### Fixed
- **x402 v1 endpoints are no longer reported as broken.** A recognised v1 envelope
  (which real JPYC deployments still emit) used to accrue four gating failures
  (RS-PR-001 version, plus the v2-required `resource` / `maxTimeoutSeconds` shape via
  RS-PR-002/005 and RS-HS-004) and read as NOT CONFORMANT. The version-shape checks
  now SKIP on a recognised v1 endpoint and bucket it under RS-PR-001 ("speaks v1, not
  v2"), while the version-agnostic rail checks (network/asset/amount/extra) still run.
  An *unknown* `x402Version` is still a FAIL. (Surfaced via a real JPYC-on-Polygon run.)
- **FA-SUP-001** no longer fails a facilitator that omits `GET /supported`. The
  endpoint is optional (CORE §7.3) — payment requirements are carried inline in the
  402 challenge — so an absent `/supported` (404/unreachable) is now a SKIP, not a
  FAIL. A *present but malformed* `/supported` (200 + non-JSON, or missing keys) is
  still a failure. Previously the suite flagged every non-CDP/facilitator-less
  endpoint as non-conformant. (Reported via a real JPYC-on-Polygon facilitator.)

### Changed
- Signed EIP-3009 payloads now default to `validAfter = 0` and a 300s timeout
  window, matching the reference client since x402#2601 ("validAfter patch").
- **RS-PR-008** now performs full EIP-55 checksum validation on mixed-case EVM
  asset addresses (via keccak when `[evm]` is installed); all-lowercase
  addresses remain a valid unchecksummed form. Previously format-only.
- **RS-SEC-011** also flags a resource-marker leak on the extreme-amount
  rejection path (consistent with the other active checks).
- `check` warns when `--resource-marker` is passed without `--active` (no effect).

### Security
- The Markdown report now neutralizes endpoint-controlled content (`detail` and
  other cells): collapses line breaks and escapes table/Markdown/HTML
  metacharacters (`| < > \` [ ]`), so a hostile endpoint can't inject raw HTML,
  links, or table-structure breaks into an operator's report. The target URL is
  sanitized inside its inline-code span too. (The JSON report was already safe
  via `json.dumps`.)

### Tests / tooling
- Catalog↔code drift guard: tests assert every implemented check ID appears in
  `conformance-catalog.md` and that its "Implemented & tested (N)" count matches
  the code (covers registry-less RS-PAY/FA-SET groups too).
- Stricter report-schema tests (format-checked timestamp, rejects unknown
  status, additional properties, and missing required fields).
- `tools/verify_new_features.py` + `--bug-leak`/`--bug-crash-huge`/
  `--bug-bad-checksum` modes in the calibration target for live verification.

## [0.1.0] — 2026-06-11

First working release. Black-box conformance testing for x402 V2 payment
endpoints, from the 402 handshake through real on-chain settlement.

**Spec baseline:** x402 Protocol v2, `x402-foundation/x402` @ `d454eb9` (2026-06-08).

### Added
- **Passive checks** (`check`): RS-HS-001…007 (handshake) and RS-PR-001…014
  (PaymentRequired schema), including cache-control, CAIP-2 namespace
  consistency, and strictly-positive amount.
- **Active negative checks** (`check --active`): RS-NEG-001/002/003/005/006/007/
  008/009/013/014 and RS-SEC-010 (cross-chain signature replay). Independent
  EIP-3009 signing (eth-account), proven byte-identical to the reference SDK.
- **On-chain settlement** (`check --pay`): RS-PAY-001…004 (positive path + tx
  verification) plus RS-SEC-001 (replay) and RS-SEC-002 (concurrent race).
- **Facilitator checks**: `facilitator` (FA-SUP-001/002, FA-VER-002, FA-ERR-001)
  and `facilitator --settle` (FA-SET-001/002/003, incl. double-settle).
- **Discovery checks** (`discovery`): DI-001/002.
- **CLI**: `check`, `facilitator`, `discovery`, `version`; JSON + Markdown
  reports; CI-friendly exit codes (0 conformant, 1 not, 2 unreachable).
- **On-chain harness** (`onchain/`, `tools/`): `MockUSDC.sol` (faithful EIP-3009
  token with on-chain signature verification + nonce tracking),
  `onchain_facilitator.py` (real web3 settlement), `calibration_target.py`
  (verify-capable reference), `onchain_smoke.py` (end-to-end smoke test).
- 94 offline tests (httpx MockTransport), mypy strict clean, GitHub Actions CI
  on Python 3.11/3.12/3.13.

### Verified
- Calibrated against a verify-capable reference target (non-circular: suite
  signs independently, target verifies with SDK primitives) — zero false
  positives; deliberately-buggy variants caught.
- Full on-chain block confirmed live against local Anvil (chain-id 84532): real
  settlements, real funds moving, replay/race/double-settle all rejected.

### Known limitations
- Settlement checks need an EVM testnet (Anvil or Base Sepolia) and a funded
  signer; the core passive suite is chain-free.
- Planned-but-unshipped checks are listed in `docs/conformance-catalog.md`.

[0.1.0]: https://github.com/x402-foundation/x402
