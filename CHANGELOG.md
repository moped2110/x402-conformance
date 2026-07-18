# Changelog

All notable changes to x402-conformance are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- **RS-SEC-008 timing-oracle probe** (`check --timing`, opt-in): checks whether an endpoint's
  rejection *time* leaks which validation failed — a wrong-signature payment (fails early, at
  signature recovery) vs. a valid-signature wrong-amount payment (fails later) that reject with
  markedly different timings expose a side channel. MINOR/advisory — never gates the verdict —
  and conservative: it flags only a gross, reproducible gap (median difference both above a 25 ms
  floor AND several times the within-class noise), so normal jitter can't false-positive. The
  decision (`classify_timing`) is pure/deterministic; the measurement clock is injectable.
  Catalog 62 → 63.
- **Run records (on by default)**: every `check` run now persists a structured, integrity-checksummed
  JSON record — UTC timestamps, tool + spec version, the exact invocation inputs, environment,
  the full per-check results, the verdict, and a `runId` content hash — plus a one-line append to
  `runs.jsonl`. Written to `./x402-runs` by default; `--log-dir` changes the path, `--no-log`
  (or the `X402_CONFORMANCE_NO_LOG` env var) disables it. **Unreachable/failed runs are recorded
  too** (with an `error` field and exit code) — the audit trail captures the attempt. No secrets:
  only the signer's public address; target/RPC URLs are reduced and fingerprinted so userinfo,
  paths, queries, and fragments cannot leak. `verify_run_record()` re-hashes a record to detect
  accidental changes; the checksum is not an adversarial trust anchor.
- **Solana / SVM `exact` foundations** (opt-in `[svm]` extra: `solders`/`solana`): the building
  blocks for the forthcoming SVM check group — CAIP-2 `solana:*` network refs, program addresses,
  ATA derivation (SPL + Token-2022), the `TransferChecked`/ComputeBudget instruction encoders, a
  partial-signed transaction builder (`build_exact_svm_transaction`, mirrors the x402 reference
  client), and tamper primitives (`SvmTamper`) for the negative checks. **Additive and
  self-contained**: no EVM path is touched, and the SVM tests skip unless `[svm]` is installed, so
  the core suite stays chain- and Solana-free. No runnable SVM checks yet — they need the
  local-validator harness; the plan is in `../SOLANA-PLAN.md`.

### Fixed
- **Payment modes now fail closed outside explicit test networks.** A central
  safety policy rejects mainnet and unknown CAIP-2 networks before payload
  construction. Positive resource/facilitator settlement additionally requires
  a funded testnet key and a matching RPC `eth_chainId`; transactional modes can
  no longer be enabled by a loosely typed auto-discovered TOML config.
- **Signed payment material is never forwarded through redirects.** Resource
  payment requests, facilitator `/verify` and `/settle` bodies, and RPC chain-id
  probes disable redirects per request, including for externally supplied HTTP
  clients. Cross-origin redirects and HTTPS downgrades therefore receive neither
  `PAYMENT-SIGNATURE` nor settlement JSON.
- **`runs.jsonl` journal now carries the verdict.** The append-only index dropped `exitCode` and
  `error` (only the full per-run JSON had them), so a directory of runs couldn't be grepped for
  failed/unreachable runs. Both fields are now in the journal line.
- **A server-error handshake is now *unreachable* (exit 2), not a MAJOR FAIL.** A 5xx to the unpaid
  probe (e.g. a Cloudflare 530) is an infra failure, not a payment verdict. The passive runner now
  retries transient 5xx (429/502/503/504) and classifies a persistent 5xx-without-paywall as
  unreachable; a genuine 200-without-payment stays a FAIL.
- **`invalid_exact_evm_payload_authorization_value_mismatch` is now a first-class spec code.**
  Upstream adopted it into the TS `ErrorReasons` enum, so it moved from the local-extension set into
  `SPEC_ERROR_REASONS` (the live drift guard caught the divergence).

### Changed
- `check` warns when its target URL looks like a facilitator/discovery endpoint (`/supported`,
  `/verify`, `/settle`, `.well-known/x402`) — a passive resource check there yields a false
  RS-HS-001; the note points to the `facilitator` subcommand.

### Tooling
- **ruff pinned exactly** (`ruff==0.15.20`, `dev` extra): the formatter's output varies across
  releases, so an unpinned CI ruff and a local ruff disagreed on `format --check`. Pinning keeps
  local == CI; bump deliberately.

## [0.2.0] — 2026-07-09

Robustness, security and UX release on top of 0.1.0: a new CRITICAL check
(RS-NEG-004, foreign/reused signature), transient-fault retry, a read-only
`--pay` balance precheck, a config file, parallel active checks, progress output,
SARIF export, DI-003, and a live verify gate in CI. 62 checks, 231 offline tests.

### Added
- **`check --config`**: a TOML config (`[check]` table; auto-discovers `./.x402-conformance.toml`)
  supplies defaults for the repetitive flags (timeout, rpc-url, resource-marker, concurrency,
  active/pay/progress/quiet/fix). Explicit CLI flags always win; secrets like `--signer-key` are
  never read from config, to keep keys out of committable files.
- **`check --concurrency N` / `-c`**: run the `--active` checks on N threads (default 1 =
  sequential). Results stay in stable catalog order regardless of completion order, so reports and
  diffs remain deterministic. Guarded against misuse in the help text — parallel payment attempts
  against a third party look like abuse; use it only on your own endpoints.
- **`check --progress`**: print per-check progress (`[done/total] CHECK-ID status`) to stderr as
  the active checks run — useful for long or concurrent runs.
- **`--pay` balance precheck** (with `--rpc-url`): before sending the one real payment,
  the runner reads the signer's ERC-20 balance of the payment asset via a read-only
  `eth_call`. If it can't cover the required amount, the whole RS-PAY group is skipped with
  a clear reason and **no payment is sent** — no doomed on-chain attempt, no confusing FAIL.
  Read-only (money invariant); an unreadable balance never blocks the run.
- **Transient-fault retry** (`check --active` / `--pay`): the active runner now retries
  429/502/503/504 responses and connection-level blips (connect/read/write/pool timeouts,
  connect errors) with exponential backoff, honouring a numeric `Retry-After` (capped at 30 s).
  A conformance run over flaky infra (rate limiters, cold starts) no longer produces spurious
  findings, while a *deterministic* fault still reproduces on every attempt and is reported
  unchanged — a permanently-5xx endpoint stays a fault, and a non-retryable protocol error (the
  endpoint breaking the connection mid-response) is surfaced immediately.
- **RS-NEG-004** (`check --active`): foreign/reused signature — a payload that keeps a *valid*
  signature but claims a different `authorization.from` (so the recovered signer ≠ the claimed
  payer) must be rejected. This is the stolen/replayed-signature vector: a server that skips the
  recovered==from binding lets an attacker spend under someone else's identity. CRITICAL. Adds a
  `tamper_from` primitive to the payload builder. Catalog 61 → 62.
- **SARIF 2.1.0 export** (`--sarif` on `check` / `facilitator` / `discovery`): writes the run's
  findings (FAIL/ERROR only) as SARIF, the format GitHub code scanning and bug-bounty platforms
  ingest — so a scan's results can land directly in a repo's Security tab. Each finding references
  a rule carrying the check's title, spec ref, severity (major/critical → `error`, minor →
  `warning`) and remediation hint, with a stable `partialFingerprint` for cross-run dedup.
- **DI-003** (`discovery`): cross-fetches each listed resource's live 402 and flags a listing
  whose (scheme/network/asset/payTo) the resource doesn't actually honor — a stale listing or a
  Bazaar metadata-manipulation lure that biases an agent toward a foreign payTo/asset
  (arXiv:2605.11781 Attack IV). `amount` is excluded (dynamic pricing is legitimate, RS-PR-012).
  MINOR, capped at 5 resources, passive GETs only. Catalog 60 → 61.
- **RS-SEC-006** (`check --active`): header-smuggling robustness — an invalid v2 payment sent
  together with a contradictory legacy V1 `X-PAYMENT` header must stay rejected (the legacy
  header must not smuggle it past v2 validation) and must not 5xx-crash on the duplicate
  headers. MINOR. Adds a `send_with_headers` primitive to the active runner. (arXiv:2605.11781
  Attack III.) Catalog 59 → 60.
- **RS-SEC-003** (`check --active`): cross-resource binding — an otherwise-valid payment whose
  claimed `resource` is relabelled to a different URL must be rejected; a server that serves it
  has no payment↔resource binding, the cross-resource replay vector from arXiv:2605.11781 /
  2605.30998. MINOR/advisory (the resource label is unsigned and a single request can't prove
  the replay exploit) so it never gates the verdict. Catalog 58 → 59.
- **Explicit method selection** (`check`): the runner never changes GET↔POST implicitly;
  POST-only resources require `--method POST`, avoiding an unexpected side-effecting request.
- **`scan` command**: batch-scans many facilitator URLs from a file. `/supported`-only
  mode is read-only; resource-backed signed `/verify` probes are active, require
  `--authorize-active-verify`, never settle, and export redacted JSON for triage.
- **FA-VER-004** (`facilitator`): a facilitator must handle invalid client input (an
  EOA `asset`) with a clean `isValid:false` (HTTP 200/4xx), not a **5xx server error**.
  MINOR robustness check — the rejection itself is gated by FA-VER-003; this flags the
  *shape*. Surfaced by real facilitators (x402-rs 500s on an EOA asset; Faremeter 500s on
  a handler exception). Catalog: 57 → 58 implemented.
- **`explain` command**: `x402-conformance explain <CHECK-ID>` prints what a check tests,
  its severity, spec reference, and a fix hint — offline, no target needed. A prefix
  (`explain RS-SEC`) lists matches; no argument lists the whole catalog. Reads the built-in
  check registries so it stays in sync with the shipped checks.
- **`diff` command**: `x402-conformance diff old.json new.json` compares two `--json`
  reports and classifies every check as fixed / regressed / still-failing / added / removed
  ("did my fix work?"). Exit code 1 if any previously-passing check regressed, so it doubles
  as a CI regression gate.
- **docs/threat-model-mapping.md**: traceability from the public x402 security literature
  (arXiv:2605.11781, 2605.30998, 2603.01179) to this suite's checks — coverage, gaps, and
  the finality/reconciliation/token-quirk surface those papers do not test.
- **RS-PR-016** (`check`): validates the JP qualified-invoice metadata
  (`x-jp402.invoice`, `registrationNumber` `^T[0-9]{13}$`) on the seller's OpenAPI
  surface — where it actually lives, per the production fixtures. The runner fetches
  `/openapi.json` **only** when the live 402 advertises `jp402`, so a non-JP endpoint
  never incurs the extra request; an unreachable/absent doc is a SKIP, a
  present-but-malformed invoice FAILs. Opt-in, MINOR. (Completes the two-surface jp402
  split alongside RS-PR-015.)
- **RS-SEC-004** (`check --active`): a payment carrying a non-32-byte EIP-3009 `nonce`
  must be rejected cleanly (`invalid nonce`), not 5xx-crash a naive bytes32 parse.
  MAJOR. (Reuse of a *valid* nonce is the stateful on-chain replay case, RS-SEC-001.)
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
- **FA-SUP-002 no longer false-flags a facilitator that serves both x402 v1 and v2.**
  It assumed every `/supported` kind was v2 (required `x402Version == 2` and a CAIP-2
  network), so a real facilitator advertising a v1 kind (version 1 with a legacy network
  *name* like `base-sepolia`) alongside its v2 kind read as NOT CONFORMANT. The check is
  now version-aware: a kind must be v1 or v2 with a scheme and a non-empty network, and
  CAIP-2 is required for v2 kinds only. (Surfaced by a real run against the x402-rs
  facilitator, which serves both versions — completes the v1 awareness on the facilitator
  side, mirroring the v1 bucketing on the resource side.)
- **RS-PR-015 now matches the real JP-rail wire shape.** Against production fixtures
  (facilitator `yen402.com` / the `x402-jpyc` reference server), the live 402 carries
  the extension under **`jp402`** (no `x-`) on `accepts[]` with a per-quote **`tax`**
  breakdown — *not* `x-jp402`/`invoice`, which lives in the seller's OpenAPI doc. The
  old check looked for `x-jp402`/`invoice` on the 402 and so quietly SKIPped on a real
  JPYC endpoint. RS-PR-015 now validates the `jp402.tax` block (`excl_jpyc`/`vat_jpyc`/
  `rate`: `vat == excl * rate`, and `excl + vat` scaling onto `amount` by a power of
  ten). The qualified-invoice `registrationNumber` validation moved to the OpenAPI
  surface (`jp402.find_invoice_blocks` + `validate_invoice`). Fixtures in
  `tests/fixtures/jp402/` (contributed by kakedashi3, x402#2603 thread).
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
