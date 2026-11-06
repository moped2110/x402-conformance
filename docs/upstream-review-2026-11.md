# Upstream review: 2026-11-06 (`cb0ec5b..e7cdc70`)

Covers `x402-foundation/x402` from the reviewed pin `cb0ec5b` (2026-10-05) to
`e7cdc70` (full `e7cdc7018b76c53d9b0e497c39351609d7ae1b35`, committed 2026-11-06
07:28 Europe/Berlin), which was tip when the review was written and still tip
when it was implemented. Same method and shape as
[`upstream-review-2026-10.md`](upstream-review-2026-10.md): spec commits read, error
registry re-extracted with `tools/sync_error_registry.extract`, findings → proposed
outcome, open questions for Mario. Mario confirmed all nine recommendations on
2026-11-06; see [Decisions](#decisions-confirmed-by-mario-2026-11-06) and
[What shipped](#what-shipped). The numbered sections keep the analysis as reviewed.

The triage draft said `6a773dba` / 197 commits; tip had moved to `e7cdc70` by the
review (**201 commits**, **18 spec commits**, 12 files under `specs/`, +1695/−218). The
four post-triage commits include SVM spec #3615 (Phantom Lighthouse) and #4171.

**Cadence missed:** last review 2026-10-06, this one 2026-11-06 = **31 days** against
the 14-day commitment in `docs/support-matrix.md`, 17 days overdue. Recorded there too.

Released SDKs:
- PyPI `x402` **2.27.0** (2026-11-04). Was 2.25.0; the CI lock moves to 2.27.0 with this change.
- npm `@x402/*` **2.30.0** (2026-11-04). Was 2.28.0.
- Go **go/v2.30.0** = `3414a566` (2026-11-04 21:01 Europe/Berlin), 188 commits after the old pin; contains all 12 spec-file changes except #3615/#4171 (Lighthouse).
- Previously unreleased October items now released: the Fastify request-target fix #3577 (`606ced02`) is in v2.29/v2.30; Go auth-capture #3622 is in.

## Summary

| # | Finding | Severity for us | Proposed outcome |
|---|---|---|---|
| 1 | Error registry: +37 codes at tip (493 → 530, 29 → 31 files), 0 removals | Wrong verdict pending (drift job red once clone at new pin) | Regenerate; boundary Q on `*_server_*` code |
| 2 | SVM transaction v1 + version negotiation (#3473/#3474/#3971), `unsupported_transaction_version` | Scope/metadata (SVM passive-only) | Registry + matrix text; RS-PR-019 vocabulary check for new `extra` keys |
| 3 | `exact` multi-payee `extra.splits` (#3221); SVM amount "at least" (overpay tolerated) | New coverage candidate | RS-PR-019: `splits` must not be graded as foreign key; optional new RS-PR check (remainder > 0, splits positive ints); RS-NEG-006 unaffected (EVM exact still exact) |
| 4 | EVM batch-settlement managed voucher / facilitator custody (#3725), 9 new batch codes | Scope (BACKLOG-005) | Matrix row update; registry only |
| 5 | XRPL `upto` spec (#3023), Canton exact mechanism (#3242), AVM canonical CAIP-2 (#3894) | Scope statement | Matrix rows (passive/not assessed) |
| 6 | builder-code `m` facilitator-authored metadata (#3666) | Low: `m` must never appear in PaymentRequired/Payload | Optional: RS-PR-023 flags `m` in a 402 (advisory); calldata suffix still not assessed |
| 7 | auth-capture `voidRemainder`, collectorData = signature as received (#3965, #3203), 4 new codes | Sibling (rvf) + registry | Registry; rvf follow-up |
| 8 | Core §5/§9 `invalidMessage`/`errorMessage` documented (#3947): free-form, clients MUST match on codes | Verify no check grades message text | Audit; models are `extra="allow"`, so no false FAIL expected |
| 9 | HTTP transport: browser/CORS guidance (#3809) — SHOULDs on Expose/Allow-Headers, preflight unpaid | New coverage | Candidate RS-HS-010 (advisory): 402 exposes `PAYMENT-REQUIRED`/`PAYMENT-RESPONSE`; OPTIONS preflight not paywalled |
| 10 | SDK hardening (non-object JSON headers #4051, high-s EIP-3009 #3912, settlement override above authorized #3877, AfterSettleAbort fail-closed #3726) | Test-relevance | Candidate negative probes: non-object JSON `PAYMENT-SIGNATURE`; high-s signature (pairs with new `invalid_exact_evm_non_canonical_signature`) |
| 11 | Heading cleanup (#3863), Express link fix (#3839), SVM payer wording (#3941) | Citations only | Check SPEC_BASELINE / § references still resolve |

## 1. Registry delta (measured)

`extract(/tmp/up-tip)` vs committed `MECHANISM_ERROR_CODES`: 530 codes from 31 files,
**+37 / −0**. Groups: SVM exact (`invalid_exact_{svm,solana}_*`: Lighthouse, instruction
order, tx v1 compute budget/heap, size, ATA, preflight/postflight; 22),
`unsupported_transaction_version`, batch-settlement EVM (9), auth-capture EVM (4),
`invalid_exact_evm_non_canonical_signature`. Boundary candidate:
`invalid_auth_capture_evm_server_lifecycle_unavailable` (server-role naming; Oct
decision 1 excluded `/server/` *files*, this one sits in a facilitator-visible file —
verify before accepting; result in Decisions 3). No retirements this window. Note: the live drift test only
runs when the clone is at the reviewed pin, so it skipped while the pin was `cb0ec5b` (22 passed, 2 skipped). With the pin at `e7cdc70` it runs: 24 passed, 0 skipped. The live check also showed that the legacy `ErrorReasons` enum gained one code, `invalid_exact_evm_payload` (41 → 42), which the draft had not listed.

## 2–11
See table; details in the spec diffs `git diff cb0ec5b e7cdc70 -- specs`. None of
the window's changes produces a shipped wrong verdict on our currently active (EVM)
checks as far as this review found — contrast with Oct §1–3. Highest-value work is
registry regeneration (#1) plus `splits` tolerance in RS-PR-019 (#3).

## Open questions (as reviewed)

1. **Pin:** `e7cdc70` (tip, includes Lighthouse) vs `3414a566` (go/v2.30.0 release) vs `6a773dba` (triage).
2. **Suite lock:** `x402==2.25.0` → `2.27.0`?
3. **Registry boundary:** accept `invalid_auth_capture_evm_server_lifecycle_unavailable`?
4. **SVM/Canton/XRPL/AVM/managed voucher:** matrix rows only (out of scope for active checks)?
5. **`splits`:** tolerate only, or add a declaration check (RS-PR-028)?
6. **CORS (#3809):** new advisory check RS-HS-010, or record only?
7. **New negative probes** (non-object JSON header, high-s signature): add now or backlog?
8. **builder-code `m` in a 402:** advisory flag or ignore?
9. **Cadence:** keep 14 days (and accept the overdue note) or relax?

## Sibling repos

Nothing changed there in this review. Analogous to October, follow-ups only:

- **rvf:** auth-capture `voidRemainder` and collectorData-as-received (#3965, #3203)
  and the four new auth-capture codes belong to the lifecycle verifier that October
  already assigned to rvf. Managed-voucher custody (#3725) likewise, if rvf ever
  models batch-settlement.
- **X402testwebside:** bump the `x402-conformance` pin after the next release, with
  the catalog mirror and the check count (81 → 84).
- **psv:** none from this window.

## Deliberately not done

- **Active checks for SVM tx v1, Canton, XRPL `upto`, AVM and the managed voucher.**
  Matrix rows only (decision 4).
- **A `splits` declaration check (RS-PR-028).** Tolerate only (decision 5).
- **Grading `invalidMessage`/`errorMessage` text (#3947).** Verified that no check
  grades message text; nothing to change.
- **Settlement-override-above-authorized (#3877) and AfterSettleAbort (#3726)
  probes.** SDK hardening without a black-box signal that the unfunded probe can
  produce.
- **Release.** No version bump and no tag; the catalog heading stays v0.7.0.
- **Sibling repos.** Not touched.

## Decisions (confirmed by Mario, 2026-11-06)

All nine recommendations were confirmed, not provisional.

1. **Pin.** `.github/upstream-reviewed-commit` moves to `e7cdc70` (tip at review
   time, including Lighthouse), not the go/v2.30.0 release `3414a566`.
2. **Suite lock.** `requirements/ci.txt` moves from `x402==2.25.0` to `2.27.0`.
3. **Registry boundary.** `invalid_auth_capture_evm_server_lifecycle_unavailable`
   is checked first and accepted only if a file the facilitator ships declares it as
   a wire code; otherwise excluded as in October decision 1.
4. **Scope.** SVM tx v1, Canton, XRPL `upto`, AVM and the managed voucher get matrix
   rows only, no active checks.
5. **`splits`.** RS-PR-019 tolerates it; no new RS-PR-028.
6. **CORS.** New advisory check RS-HS-010.
7. **Negative probes now.** A non-object JSON header and a high-s signature.
8. **Builder-code `m` in a 402.** Advisory note on RS-PR-023, not ignored.
9. **Cadence.** Stays 14 days; the 31-day gap is recorded openly.

**Decision 3, result: excluded.** At `e7cdc70` the code is declared twice: in Go's
`mechanisms/evm/auth-capture/server/errors.go` (already out by the role boundary)
and in TypeScript's shared `mechanisms/evm/src/auth-capture/errors.ts`, which the
facilitator also imports. That second file is why the extractor found it. But
upstream annotates it there as *"Resource-server lifecycle manager errors (never
sent on the wire)"*, and its only use is `auth-capture/server/lifecycleManager.ts`
(and Go's `server/manager.go`), which throws it before anything reaches a
facilitator. So it is not a facilitator wire code, and it is excluded by name in
`_EXCLUDED_CODES`, next to the October minDeposit code.

**Pin form.** The decided SHA `e7cdc701` is recorded as `e7cdc70`: the drift job
compares `git rev-parse --short=7` and `test_registry` requires seven hex
characters. Same commit, verified to exist after a fresh fetch (tip unchanged).

## What shipped

Check count 81 → **84** (RS-HS-010, RS-NEG-017, RS-NEG-018). Report version unchanged
(1.5, unreleased).

| # | Change | Notes and deviations from the proposal |
|---|---|---|
| 1 | Pin `e7cdc70`; support matrix "Latest upstream review" 2026-11-06; `SPEC_BASELINE`, README, DEVELOPER updated | Seven-character form, see above |
| 2 | `requirements/ci.txt`: `x402==2.27.0` | `uv pip compile … --upgrade-package x402==2.27.0`; only the x402 entry and its hashes changed, no transitive moves |
| 3 | Registry regenerated: **529 codes from 31 files** (+36 / −0 against 493) | The extractor finds 530; `invalid_auth_capture_evm_server_lifecycle_unavailable` excluded by name. Legacy `SPEC_ERROR_REASONS` 41 → **42** (`invalid_exact_evm_payload`, already accepted through the registry, no verdict change). Live drift tests pass against the clone at the pin (24 passed, 0 skipped) |
| 4 | Support matrix rows: SVM transaction v1, AVM, XRPL `upto`, managed voucher; Canton row updated | Row only, nothing active |
| 5 | RS-PR-019: `splits` in the SVM `exact` vocabulary and tolerated on every `exact` binding | `splits` on a non-`exact` binding is still a foreign key (MINOR FAIL), because the extension is `exact`-only |
| 6 | RS-HS-010 (MINOR, advisory only) | Two extra unpaid requests, only on a paywall: the request again with `Origin: https://x402-conformance.invalid`, and the `OPTIONS` preflight. No `Access-Control-Allow-Origin` is noted and ends the check (http.md allows refusing browsers). Not graded: `Vary: Origin`, `Max-Age`, v1 spellings |
| 7 | RS-NEG-017 (MAJOR, 400 for `[]`, a string, a number, `null`); RS-NEG-018 (MAJOR, high-s twin, 400/402) | RS-NEG-018 cannot prove the low-s rule ran when the rejection reason is something else (unfunded probe signer): PASS with a note, not FAIL, unlike RS-NEG-016 — upstream puts the rule in the verifier, not in a resource-server MUST |
| 8 | RS-PR-023: `m` in the declared builder-code info → advisory PASS detail; a bad `a` still fails, with the advisory appended | |
| 9 | Cadence: 14 days kept; the missed 31 days recorded in the support matrix and here | |

Tests: `pytest` 837 passed, 4 skipped (coverage 89.9 %); ruff, ruff format, mypy
strict and the function-doc check clean. New: `tests/test_upstream_2026_11_checks.py`.

## Follow-ups (not in this change)

- **Release** (new checks), including the catalog heading bump.
- **Drift job.** It turns green once this change is on `main`; the tip moves daily, so
  the next review starts from `e7cdc70`. Next due: 2026-11-20.
- RS-HS-010: `Vary: Origin`, `Access-Control-Max-Age`, the v1 header spellings.
- RS-PR-019: grading `splits` contents (positive amounts, remainder > 0) if wanted.
- Sibling follow-ups above (rvf, X402testwebside).
- `RETIRED_ERROR_CODES` removal on or after 2027-04-06 (unchanged).
