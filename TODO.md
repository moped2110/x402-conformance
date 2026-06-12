# TODO — x402-conformance

Working backlog for the suite. Tasks live here; findings go to `docs/`.

**Conventions:** Tasks have stable IDs (`T-nn`), a priority (P1 = blocks v0.1 release, P2 = should-have for v0.1, P3 = after launch), effort (S ≤ 1 evening, M ≤ 1 weekend, L = multiple sessions), and explicit acceptance criteria. Finished tasks move to the Done section with date — never delete them.

**Status:** updated 2026-06-09 · Milestone M1 = OSS release v0.1

---

## Milestone M1 — OSS release v0.1

### T-01 · P1 · L — Implement RS-NEG check group (negative tests)
The core value proposition: prove that endpoints reject what they must reject. First non-passive test group — requires actively constructed (invalid) payments.

Subtasks:
1. ☑ `PaymentPayload` builder for exact/eip3009 (EIP-712 signing via `eth-account`, optional dep `[evm]`) — done in `payload_builder.py`, signature proven byte-identical to reference SDK (keystone test).
2. ☑ Tamper toolkit: signature, value-lower, recipient, expired, not-yet-valid, accepted-amount — done + unit-tested. Remaining mutations for full coverage: wrong-asset (RS-NEG-014), wrong-chain-id (RS-SEC-010), malformed/garbage payloads (RS-NEG-001/002).
3. ☑ **Active-request runner** (`active.py`): probes requirements, builds a payment sender (`send`/`send_header`), parses settlement responses.
4. ☑ Wire RS-NEG checks (`checks/negative.py`): 001, 002, 003, 005, 006, 007, 008, 009, 013, 014 + RS-SEC-010. 11 active checks.
5. ☑ CLI flag `--active` (default passive) + throwaway signer ($X402_TESTNET_PAYER_KEY / --signer-key / random).
6. ☑ Calibration: DONE. `tools/calibration_target.py` (verify-capable via SDK digest, non-circular) → correct server 31 passed / 0 failed; buggy variants caught precisely. See `docs/active-checks-2026-06-10.md`.

Remaining for full closure: RS-PAY positive path + balance-dependent rejection (need RPC/chain), RS-SEC-001/002/003 (replay/race — need stateful/settled endpoint), content-leak body inspection.
Status: **RS-NEG group done and calibrated**; on-chain settlement is the next frontier.

### T-02 · ☑ DONE (2026-06-10) — LICENSE file
Apache-2.0 chosen. `LICENSE` added, matches pyproject.

### T-03 · ☑ DONE — Initialize git repo
`git init -b main`, Conventional Commits, `.gitignore` verified (no `.env`, no `__pycache__`).

### T-04 · P2 · M — Calibrate against further reference servers
So far only FastAPI. Add Flask (Python) and one Node server (Express or Hono).
Acceptance: at least flask + one Node server run conformant; deviations documented in `docs/`.
Depends on: Node toolchain in dev setup.

### T-05 · P2 · M — File upstream issues for the calibration findings
From `docs/calibration-2026-06-09.md`: (1) undocumented facilitator capability fields, (2) silent 500 on requirements-building error, (3) invalid bazaar extensions in the e2e server.
Precondition: re-verify against current upstream `main` before filing.
Acceptance: issues/PRs filed upstream.

### T-06 · ◐ partly DONE (2026-06-10) — Facilitator check group (FA-*)
Done (chain-free): FA-SUP-001/002, FA-VER-002, FA-ERR-001 + `facilitator` CLI
command, offline tests, live calibration via `tools/calibration_target.py`
(correct → all PASS; `--bug-no-amount` → caught). See
`docs/facilitator-checks-2026-06-10.md`.
Remaining (need RPC/chain → on-chain day): FA-VER-001 (valid→true, balance),
FA-VER-003 (no-settle), FA-SET-001/002, FA-SET-003 (double-settle/nonce).

### T-14 · ☑ DONE (2026-06-10) — Discovery check group (DI-*)
DI-001 (schema + pagination) and DI-002 (network filter honored) + `discovery`
CLI command + offline tests (correct/buggy Bazaar). DI-003 (staleness vs. live
402) deferred — needs cross-fetching each listed resource.

### T-15 · ☑ DONE (2026-06-12) — RS-SEC-009 marker-based content-leak refinement
`check --active --resource-marker <s>` flags a rejected response whose body still
contains the protected content. Detected at response-build time; enforced in
every active check via `_assert_rejected`. Tests added.

### T-16 · ☑ DONE (2026-06-12) — RS-SEC-011 extreme-amount robustness
Active check: signs a 2²⁵⁶-1 amount; FAILs on a 5xx crash or if the endpoint
accepts it, PASSes on a clean rejection. Tests added.

### T-07 · ☑ DONE (2026-06-12) — Finalize report format (versioned JSON schema)
`report.schema.json` (draft 2020-12) at the repo root; `to_json` emits
`reportVersion`. CI validates output against the schema. `jsonschema` added to dev.

### T-08 · ☑ DONE — CI pipeline (GitHub Actions)
pytest + mypy on every push. Workflow present, runs green.

---

## After M1 (P3)

### T-09 · P3 · S — Decide testnet strategy
How to test RS-PAY-004 (real on-chain settlement) cost-effectively. Options: verify-path only, mocked settlement, or a dedicated nightly run against Base Sepolia with faucet USDC. Partially blocks T-01 (only the settlement cases).

### T-10 · P3 · L — RS-SEC check group (replay / race / robustness)
Catalog §5: replay-after-settlement, parallel race, cross-resource replay, oversized header.
Depends on: T-01 (payload builder), T-09 (race tests need real settlement).

### T-11 · P3 · M — Extended scheme coverage
`upto`, `batch-settlement`, Permit2/ERC-7710, SVM exact. Only once ecosystem usage justifies it — check adoption at implementation start.
Design sketch (mechanism abstraction + EVM permit-style + SVM exact): `docs/design-extended-schemes.md`.

### T-12 · ☑ DONE (2026-06-12) — EIP-55 checksum validation for asset addresses (RS-PR-008)
RS-PR-008 now validates the EIP-55 checksum on mixed-case EVM asset addresses
(keccak via eth_utils when `[evm]` is present); all-lowercase stays a valid
unchecksummed form; format-only fallback without keccak. Tests added.

### T-13 · P3 · M — Hosted monitoring layer
Optional future direction: continuous checks + alerting. Out of scope for v0.1.

---

## Open decisions
1. **T-09:** Testnet strategy — how far to test real on-chain settlement.
2. **Sequencing:** T-01/T-02 first (negative tests, the product core) or T-05 first (upstream issues).

---

## Done
- 2026-06-12 — T-07/T-12/T-15/T-16: versioned `report.schema.json` (+`reportVersion`, CI-validated), RS-PR-008 full EIP-55 checksum validation, `--resource-marker` content-leak detection (RS-SEC-009 path), RS-SEC-011 extreme-amount robustness check. 102 offline tests, mypy strict clean.
- 2026-06-11 — **v0.1.0 release prep**: catalog implementation-status section, CHANGELOG.md, version bump 0.0.1→0.1.0, GitHub Actions CI (pytest+mypy on 3.11–3.13). 94 tests, mypy clean.
- 2026-06-11 — On-chain block complete (RS-PAY, RS-SEC-001/002, FA-SET) confirmed live against Anvil; MockUSDC + onchain_facilitator + smoke test. See `docs/onchain-2026-06-11.md`.
- 2026-06-10 — DI discovery group (DI-001/002) + `discovery` CLI command + tests.
- 2026-06-10 — Internal infrastructure tests added (models, probe stages, report/exit-codes/JSON, registry integrity, CLI exit codes): 85 tests total, mypy clean across 15 modules. The tool's own scaffolding is now test-covered, not just the checks.
- 2026-06-09 — Project skeleton, models, probe, check registry, CLI, reports (RS-HS + RS-PR groups), 20 offline tests, mypy strict clean.
- 2026-06-09 — Calibration against upstream FastAPI reference server: 7/7 endpoints conformant, zero false positives. See `docs/calibration-2026-06-09.md`.
- 2026-06-10 — Triaged the x402 testcase set (see `docs/testcase-integration-analysis.md`); added 6 new black-box checks (RS-HS-007 cache, RS-PR-013 namespace, RS-PR-014 amount>0, RS-NEG-014 wrong-asset, RS-SEC-010 cross-chain-replay, RS-SEC-011 overflow). 3 passive ones implemented + tested.
- 2026-06-10 — T-02 payload builder + tamper toolkit (`payload_builder.py`), independent eth-account signing proven byte-identical to reference SDK. 37 tests, mypy clean. Apache-2.0 LICENSE added.
- 2026-06-10 — T-01 core: active-request runner (`active.py`) + 11 RS-NEG/RS-SEC-010 active checks (`checks/negative.py`) + CLI `--active`. 42 tests (correct mock → all PASS, buggy mocks → caught), live socket smoke test green, mypy clean. See `docs/active-checks-2026-06-10.md`.
- 2026-06-10 — RS-NEG live calibration via `tools/calibration_target.py` (SDK-digest verify, non-circular): correct → 31/0, buggy variants caught.
- 2026-06-10 — T-06 (partial): FA facilitator group (FA-SUP-001/002, FA-VER-002, FA-ERR-001) + `facilitator` CLI command. 47 tests, mypy clean, live-calibrated. See `docs/facilitator-checks-2026-06-10.md`.
