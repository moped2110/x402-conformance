# Upstream review: 2026-10-06 (`f62a9fa..cb0ec5b`)

This review covers `x402-foundation/x402` from the previously reviewed pin `f62a9fa`
(2026-08-12) to `cb0ec5b` (2026-10-05). The window has 180 commits. They touch 25
spec files (+4987/−419) and the error registry moves +211/−17. Upstream also made
four fixes to the paywall path-matching class and shipped one new scheme family
(SVM batch-settlement) and three new network bindings (Lightning, Cardano and
Hedera's `transferExecutor`). This document records what was assessed, what Mario
decided on the open questions (all eight confirmed on 2026-10-06), and what shipped.
The numbered sections keep the analysis as reviewed; their **Proposed** paragraphs are
the plan, and [What shipped](#what-shipped) records the result, including where the
implementation deliberately differs.

The weekly `Supply chain` drift job is red. The review is 54 days old and the
support matrix commits to 14, so the cadence alarm is working as designed. The job
also re-runs the registry drift test, which fails against `cb0ec5b` because of the
registry delta in §6. The job only turns green once the pin, the matrix date and
the registry all move together, and this change moves all three.

Released SDKs at the time of writing:

- **PyPI `x402`:** 2.25.0 (2026-09-29). It was 2.19.0 at `f62a9fa`. Our CI lock already pins 2.25.0.
- **npm `@x402/*`:** all packages at 2.28.0 (2026-09-29). They were 2.22.0 at `f62a9fa`. The legacy `x402` packages are frozen at 1.2.0.
- **Go:** `go/v2.28.0`.

Four upstream changes in this window are **not in any release yet**:

- the Fastify request-target fix (#3577);
- Go auth-capture (#3622);
- the SVM batch fixes (#3655/#3661/#3664);
- the Python batch-baseline fix (83554354).

## Summary

| # | Finding | Severity for us | Outcome (all shipped unless noted) |
|---|---|---|---|
| 1 | Bazaar `lastUpdated` is an ISO 8601 string; DI-001/DI-002 require a number | **Wrong verdict shipped** | Fix DI-001/002 + `DiscoveryItem` |
| 2 | `settlement_pending`: failed settle with a non-empty `transaction` is now legal | **Wrong verdict shipped** | Fix model + FA-SET-001/002/003, RS-PAY-001/002 |
| 3 | RS-PR-019 vocabulary is EVM-exact vs SVM-upto only | **Wrong verdict shipped** (pre-existing, surfaced now) | Make it binding-aware |
| 4 | RS-PR-026 signals are stale (auth-capture v1.1, SVM batch) | Misleading advisory | Make it scheme-aware |
| 5 | Fastify absolute-form request-target bypass (#3577), unreleased fix | Missing critical coverage | RS-SEC-012 variant |
| 6 | Error registry +211/−17; one role leak, one extractor blind spot | Wrong verdict pending on regeneration | Regenerate with boundary decisions |
| 7 | `upfront` now legal for `exact`; per-binding flow constraints | New coverage | RS-PR-027 |
| 8 | EXTENSION-RESPONSES sidechannel (§7.2.1) | New coverage | RS-HS-009, FA-EXT-001 |
| 9 | builder-code `a` echo now enforced by the resource server | New coverage | RS-NEG-016 |
| 10 | auth-capture v1.1 (`autoCapture` removed, operator types, new deployments) | New coverage + sibling impact | RS-PR-027 rules; rvf verifier |
| 11 | Lightning, Cardano, Hedera `transferExecutor`, SVM batch-settlement, SVM upto delegated | Scope statement | Matrix rows |
| 12 | Starknet/Hedera settle-semantics clarifications | Already aligned | psv citations (sibling repo, not here) |
| 13 | New default-asset networks | Metadata | Optional allowlist (deferred) |
| 14 | SIWX origin binding, SVM `upfront` guidance, minor spec edits | Verified, no action | Recorded |

## 1. DI-001 and DI-002 fail every current Bazaar

This window, like the first one in August, gives us a wrong verdict that we are
already shipping, and it sits on MAJOR checks.

`specs/x402-specification-v2.md` §8 (#3067, 240492ed) changes the example and
table so that `lastUpdated` is an ISO 8601 string, drops `metadata`, and moves the
example to `x402Version: 2`. The commit message states that all six reference
facilitators *already* emit ISO strings and that every SDK client types the field
as a string. The spec caught up with the wire. Our checks did not.

- `checks/discovery.py::_validate_discovery_body` requires
  `lastUpdated` to be "a non-negative finite number". A scratch probe confirms that
  an ISO string is reported as a problem. The helper backs DI-001 and both DI-002
  paths, and both checks are MAJOR, so every real Bazaar fails a gating check.
- `models.DiscoveryItem.last_updated: int = Field(alias="lastUpdated", ge=0)` is
  wrong for the same reason. It is strict, so it does not coerce.

**Proposed.** Accept an RFC 3339 / ISO 8601 string. Emit a single advisory if a
number is still seen; do not fail on it, because the old spec allowed numbers and
older facilitators may still send them. Add fixtures for both shapes and a test
modelled on the real CDP `/discovery/resources` response. Priority **must**.
Effort S.

## 2. `settlement_pending` breaks the settle-response model

CORE §5.3 / §9 (6dba93ed, #3083; released py 2.20 / npm 2.23 / go 2.23):

> `transaction` — empty string if no transaction was broadcast; MUST be non-empty
> when `errorReason` is `settlement_pending`.

The facilitator MAY answer `success: false, errorReason: "settlement_pending",
transaction: <hash>` when it broadcast a transaction but could not confirm it. The
outcome is non-terminal. The EVM `exact`, `upto` and `batch-settlement` bindings
allow it explicitly. #3214 (82ba36f2, py 2.21 / npm 2.24 / go 2.24) adds the server
side: `PendingSettlementStore` plus `settle_with_pending_retry`. The server retries
`/settle` once, and the facilitator reconciles against the stored hash instead of
re-broadcasting.

Our model forbids exactly this:

```python
elif self.transaction:
    raise ValueError("failed settlement must not carry a transaction")
```

A scratch probe confirms that the model rejects a spec-conformant pending response.
The consequences follow from there:

| Check | Today | Should be |
|---|---|---|
| FA-SET-001 | FAIL "invalid response" | `settlement_pending` + tx → INCONCLUSIVE (pending), not FAIL |
| FA-SET-002 | FAIL "failed settle carries tx" | A failed settle with a tx is legal (pending, or broadcast-then-reverted). Drop the tx rule here; the inverse rule (pending MUST carry a tx) moves to FA-SET-004 |
| FA-SET-003 | FAIL on any second success | Same hash as a pending first answer = idempotent reconciliation, PASS; a different hash = double spend, FAIL |
| RS-PAY-001 | FAIL when `success` is false | Pending → INCONCLUSIVE with a "reconcile <hash>" note |
| RS-PAY-002 | FAIL `settlement_error` (model rejection) | Parse cleanly; grade separately |
| RS-NEG-* (`negative.py:85`) | FAIL "malformed PAYMENT-RESPONSE" | Keep strict: a *rejected invalid* payment must not carry a tx. That is a semantic rule, not a model rule |

**Proposed.**

- Relax the model so that `success: false` may carry a transaction. Require one
  when `errorReason == "settlement_pending"`.
- Move "a rejected payment carries no tx" into the checks that actually mean it.
- Add `settlement_pending` to the spec-core codes. It is in §9, and the registry
  regeneration already picks it up.
- Add FA-SET-004 (MINOR): a `settlement_pending` response MUST carry a non-empty
  `transaction`.

Priority **must**. Effort M.

## 3. RS-PR-019 fails conformant SVM, Hedera, Starknet and EVM-upto entries

This bug predates the window, but this window turned it up and makes it worse.
RS-PR-019 (MINOR) knows two vocabularies: `exact` = `{name, version}` (EVM) and
`upto` = SVM channel fields. Any `exact` entry carrying `feePayer` or
`recentBlockhash` fails, and so does any `upto` entry carrying `name`/`version`.
The scratch probe FAILs all five of these spec-conformant shapes:

- exact SVM (`feePayer` + `recentBlockhash`);
- exact SVM `upfront`;
- upto EVM (Permit2 `name`/`version`);
- exact Hedera (`feePayer`, new this window);
- exact Starknet (`feePayer`).

**Proposed.** Key the vocabulary on (scheme, CAIP-2 namespace), with entries for:

- exact/eip155;
- exact/solana;
- exact/hedera;
- exact/starknet;
- exact/lnbtc (`requestHash`, bolt11 fields);
- exact/cardano;
- upto/eip155;
- upto/solana;
- batch-settlement/eip155;
- batch-settlement/solana;
- auth-capture/eip155.

Only grade combinations we have a vocabulary for, and SKIP unknown namespaces. Do
not fail them. Update the `report.py` RS-PR-017 explanation text, which still lists
only three schemes. Priority **must**: a shipped false FAIL, even at MINOR. Effort M.

## 4. RS-PR-026 advises on the wrong signals

RS-PR-026 infers "this looks like escrow but does not say so" from
`{withdrawDelay, receiverAuthorizer, autoCapture}`. That inference is now wrong in
three ways:

- **SVM `batch-settlement`** (`scheme_batch_settlement_svm.md`, #2698) carries
  `receiverAuthorizer` and `withdrawDelay`, but its flow, when present, MUST be
  `authorization`. We advise it to declare escrow, which is the opposite of the
  spec.
- **auth-capture v1.1** removed `autoCapture`. `autoCapture: true` must now be
  rejected. We still treat it as an escrow signal.
- **auth-capture with no `paymentFlow`** SKIPs. The scheme default is `escrow`,
  which hits the same CORE-vs-binding contradiction recorded for SVM `upto` in
  August.

**Proposed.** Make it scheme-aware and keep it advisory. The upstream
contradiction is unchanged, and auth-capture now joins SVM `upto` in it. Priority
**should**. Effort S.

## 5. RS-SEC-012: absolute-form request-target bypass (#3577)

606ced02 (2026-10-02), "fastify: reject non-origin-form request targets". Fastify
routes on the path of an absolute-form target (`GET http://host/paid HTTP/1.1`),
but the payment middleware read the raw `request.url`, so the route did not match
and the request reached the paid handler unpaid. The fix answers 400 to any
non-origin-form target.

**The fix is unreleased.** `@x402/fastify` 2.28.0 (2026-09-29) does not contain
it, so every Fastify deployment today is exposed. This is the sixth fix to the path
class in this window:

- #3502 6323ec74 (Python literal-route `%2F`);
- #3542 5d3a2b2c (TypeScript escaped+decoded matching);
- #3543 279f12cf (Go escaped+decoded matching);
- #3440, #3441 and #3213 (routeTemplate fixed-point decode).

Our encoded-separator variant already covers the separator cases.

**Proposed.** Add an `absolute-form` variant. httpx always sends origin-form, so
this needs a raw-socket request (TLS-wrapped for https targets) to satisfy
`test_no_variant_is_inert_on_the_wire`. The verdict is PASS on 400 or 402 and FAIL
on 2xx with the paid body. Asterisk-form and authority-form are worth a look under
the same harness. Priority **must**. Effort M.

## 6. Error registry: +211/−17, and where the boundary should sit

`tools/sync_error_registry.py` against `cb0ec5b`: **344 → 538 codes across 38
declaring files, +211 / −17**. The method is reproducible with the existing
patterns and exclusions. A hint from a quicker look said +216/−22; the difference
is most likely a different HEAD.

The additions, by declaring file:

| Source | Added | Wire codes? |
|---|---|---|
| core `settlement_pending` | 1 | Yes (§9) |
| go auth-capture facilitator | 50 | Yes |
| **go auth-capture `server/errors.go`** (`invalid_auth_capture_evm_server_*`) | 23 | **No.** Route/config/manager/settlement-hook errors, wrapped in `fmt.Errorf` with suffix text, raised at server start-up or in hooks |
| batch EVM `deposit_below_min_deposit` | 1 | Server-returned only; facilitator MUST NOT enforce |
| go SVM exact facilitator (smart-wallet path, #3263) | 24 | Yes |
| go SVM upto client / facilitator / server | 15 / 28 / 8 | Facilitator yes; client and server no |
| TS Casper facilitator / server | 20 / 5 | Facilitator yes; server no |
| TS SVM exact facilitator | 36 | Yes |

The removals:

- 8 `invalid_exact_evm_server_*` and 8 `invalid_upto_evm_server_*`. These are
  money-parsing errors, removed with the spend controls in 5246387a.
- `invalid_exact_solana_payload_amount_insufficient`, replaced by
  `_amount_mismatch` (#3263). Go facilitators that are already deployed will keep
  returning it.

**The boundary question August left open is now concrete.** 92 registry codes
come only from `/client/` or `/server/` declaring files: 41 were already in the
344, and 51 are new. In August the line was drawn at `RouteValidationError` because
it was the only leak in view. The same argument covers every role-scoped file: a
resource server's start-up error never reaches a `VerifyResponse`, and accepting
one in FA-ERR-001 weakens the check.

**Extractor blind spots:**

- Cardano TS declares `export const ERR_*`, which the TS pattern
  (`Err\w+`) misses. That is **47 codes**, all wire codes.
- Hedera, Aptos, Keeta, XRPL, Stellar, Concordium and NEAR return inline
  `invalidReason: "..."` literals. These were never captured, and the gap predates
  this window.

**Proposed** (see open questions):

- Regenerate.
- Exclude role-scoped client and server files.
- Keep removed codes as a *retired but accepted* set, so a facilitator that has
  not upgraded is not failed.
- Widen the TS pattern to `ERR_\w+`.
- Record the inline-literal mechanisms as a known gap in the generator's header.
- Keep `deposit_below_min_deposit` out of facilitator-graded vocabulary.

Priority **must**, because the drift job cannot go green otherwise. Effort M.

## 7. `upfront` for `exact`, and per-binding flow constraints

`scheme_exact.md` (#3145, 23173acb; SDK support bb46ffc6/f8dfe4da):

- `exact` MAY use `upfront`.
- `authorization` SHOULD be preferred, and clients SHOULD pick it when both are
  offered.
- `upfront` defines no refund.
- A new "asset transfer method families" section: client-submitted (proof)
  methods MUST use `upfront`.
- `scheme_exact_svm.md`: long-running handlers SHOULD use `upfront`, because a
  blockhash expires in roughly 60–90s.

`paymentFlow` stays the right field, and RS-PR-025 already accepts `upfront`.
What is new is the per-binding constraint each spec states:

| Binding | Constraint |
|---|---|
| `upto` (any) | MUST NOT be `upfront` |
| exact/lnbtc | MUST be `upfront` (`assetTransferMethod: bolt11`) |
| exact/starknet | always `authorization`, method `default` |
| exact/cardano | `authorization`; field not emitted |
| batch-settlement/solana | if present, MUST be `authorization` |
| upto/solana | `escrow` |
| auth-capture | `escrow` (default) or `authorization`; `autoCapture: true` → reject |

**Proposed.** Add **RS-PR-027** (MAJOR where the spec says MUST, advisory where it
says SHOULD), grading `paymentFlow` against the binding.

`active.py::choose_eip3009_requirement` takes the first matching entry and ignores
the flow. Make it prefer `authorization` when both are offered, as the client
SHOULD; otherwise our active probes may settle before the handler without meaning
to.

RS-PR-018 groups duplicates by (scheme, network, asset). Two entries that differ
only in `paymentFlow` are legitimate under #3145, so the group key needs the
reserved keys. That is a potential false FAIL; it is not seen live yet.

Priority **should**. Effort M.

## 8. EXTENSION-RESPONSES (§7.2.1)

1bc2ae8c (#3278), e187dda1 (#3306) and eb0d899e (#3301), released py 2.22 /
npm 2.25:

- A facilitator MAY return an `EXTENSION-RESPONSES` header on `/verify` and
  `/settle`, containing base64 JSON keyed by extension name.
- `VerifyResponse` gains optional `extensions`.
- `bazaar.md` now has a three-channel table. EXTENSION-RESPONSES is "server
  internal only; never forwarded to the buyer", and the sentence telling clients
  they SHOULD read it is gone.

**Proposed:**

- **RS-HS-009** (MAJOR): the header MUST NOT appear on the 402 or the paid 200.
  It is passive on the paid response.
- **FA-EXT-001** (MINOR): if present on `/verify` or `/settle`, it decodes to a
  JSON object keyed by extension.
- Let `extensions` through on the `VerifyResponse` model. It already passes, since
  `extra="allow"`; add a fixture so that stays true.

Priority **should**. Effort S–M.

## 9. builder-code: the resource server now owns `a`-echo validation

a3c6004b (#3313), 6c1a4b27 (#3302), 3e9631d5 (#3320), docs 138d415f. The
validation step moves from the facilitator to the **resource server**. The server
MUST reject (`extension_echo_mismatch`) a v2 payment whose `a` is present and
differs from `info.a`. This includes the case where the server declared no `a` at
all. The facilitator step was removed. RS-PR-023/024 grade the declaration and
remain correct.

**Proposed. RS-NEG-016** (active, MAJOR): send a payment whose builder-code echo
does not match, and expect the server to reject it with `extension_echo_mismatch`
*before* contacting the facilitator. Check that no settlement header appears.
Priority **should**. Effort S on top of the RS-NEG harness.

## 10. auth-capture v1.1

f8a3682d (#3197, 2026-08-18), 44f6b178 (#3283), 4999dc63 (#3354), and Go SDK
support in cb0ec5bc (#3622, unreleased):

- **Operator types.** `operatorType` is `delegated` or `custom`; `policy` is
  reserved.
- **Capture mode.** `captureMode` is `sync` or `deferred`, with rules per
  operator type.
- **Lifecycle.** The operations are `/settle` calls with `payload.type`:
  authorize, charge, capture, void, refund and reclaim. One `/settle` call may
  capture-and-void.
- **Single use.** Enforced through `paymentState`.
- **`/supported` extra.** It carries `captureAuthorizer`, `receiverAuthorizer`
  and an operator allowlist.
- **`autoCapture` removed.** `autoCapture: true` MUST be rejected.
- **New deployments.**
  - v1.1: escrow `0xf968…B19c`, plus EIP-3009, Permit2 and refund collectors.
  - v1.0: escrow `0xBdEA…0cff`.
  - A v1.0 client cannot pay a v1.1 server.

For x402-conformance, the declaration rules belong in RS-PR-027 (§7) and the
RS-PR-026 fix (§4). Lifecycle semantics stay out of the suite, as in August.
This version of the scheme matters more for **rvf**: its escrow model
(`detect_escrow_divergence`) treats more than one disposition event as
`DOUBLE_DISPOSITION`. A legitimate partial capture plus void, multiple captures, a
refund after capture, or a reclaim after `captureDeadline` would all be
false-CRITICAL there. See the sibling-repo notes below.

## 11. Scope: new bindings

Matrix rows, all `planned` unless noted:

- **Lightning `exact`** (`scheme_exact_lnbtc.md`, #2861).
  - Networks: `lnbtc:000000000019d6689c085ae165831e93` (mainnet) and
    `lnbtc:000000000933ea01ad0ee984209779ba` (testnet).
  - Asset `"BTC"`; method `bolt11`; flow `upfront` only; `extra.requestHash`
    (JCS).
  - The server MUST NOT call `/verify`, so a lnbtc facilitator is not
    FA-VER-gradeable.
  - Our CAIP-2 regex already accepts the network IDs, and the probe shows
    RS-PR-001..026 pass a conformant entry.
- **Cardano `exact`** (`scheme_exact_cardano.md`; TS SDK #2537).
  - Networks `cardano:mainnet`, `cardano:preprod` and `cardano:preview`, plus
    CIP-34 aliases.
  - Methods `default`, `masumi` and `script`.
- **Hedera `exact`** (`scheme_exact_hedera.md` +513, #3205).
  - Adds the `transferExecutor` method next to `cryptoTransfer`, and
    `invalid_exact_hedera_unsupported_asset_transfer_method`.
- **SVM `batch-settlement`** (`scheme_batch_settlement_svm.md`, 1956 lines, #2698;
  fixes #3603/#3661). The extra fields are:
  - `feePayer`, `receiverAuthorizer`, `withdrawDelay` (900..2592000);
  - `tokenProgram`, `minDeposit`, `voucherSigner`;
  - `operator`, `maxIdleSecs`.
- **SVM `upto` delegated `receiverAuthorizer`** (`scheme_upto_svm.md`).
  - A settle-only `payload.type` is introduced. A client-supplied one is
    `invalid_upto_svm_payload_type`.
- **EVM batch `minDeposit`** (76fe9734/909b4fae/cf07e963).
  - Enforced by the server only. The not-below-claimed rule is tightened, and the
    PAYMENT-RESPONSE `extra` is untrusted.
- **Casper TS SDK** (#2877). It has no spec file and gets no row until there is
  one.

## 12. Settle-semantics clarifications we already follow

- **Starknet** (d6d2c580): a consumed nonce is terminal, and success is reported
  only for a tx the facilitator broadcast itself. Transfer events are counted per
  payer, and RPC brownouts map to `unexpected_verify_error`.
- **Hedera:** the outcome comes from consensus records, not receipt status.

Both match psv's reconcile-from-chain stance. Cite them in psv's SC1 notes.
No check change is needed.

## 13. Default assets

DEFAULT_ASSETS.md is restructured to multiple assets per network. The new
networks are:

- Monad testnet USDC `eip155:10143` (#3570);
- Arc `eip155:5042` / `5042002` (#3590);
- Sei `eip155:1329` / `1328` (#3227);
- Celo USDT and USAT (#3457).

Monad USDC's v1 domain name becomes `"USDC"` (#3153). Optionally allowlist the
testnets 10143, 5042002 and 1328 in `safety._ALLOWED_EVM_NETWORKS`. Priority
**could**. Effort S.

## 14. Verified, no action

- **SIWX** (#3133): the client MUST refuse a challenge whose origin differs from
  the 402 resource. This is client behaviour and not observable from our side.
- **Stellar CAP-71 V2 credentials** are accepted, and **Starknet executor ==
  payTo** is allowed. Neither touches our checks.
- The `solana<0.40` cap in upstream's `svm` extra (75e12f00) does not affect us:
  we do not import `solana.rpc.api`. Our `solana>=0.34` is uncapped. Watch it, but
  no change.
- FA-SVM-VER-002/003 tampers should be re-run against Go's new smart-wallet
  path (#3263, 01b0a68a). This is open, not urgent.

## Sibling repos

- **psv:**
  - Map `success:false` + tx + `settlement_pending` to a *pending* outcome. Today
    it is just "unsettled".
  - Add a pending/auto-recovery scenario: the server's one retry must not cause a
    second broadcast. PSV-CRASH-001 and PSV-I-001 are the natural neighbours.
  - Add the Starknet/Hedera citations (§12) and, optionally, new rails (Sei, Monad
    testnet, Arc, Celo USDT/USAT).
  - auth-capture stays out of reconciliation scope. The funds route through the
    collector and escrow, not payer→payee.
- **rvf:**
  - Add an auth-capture lifecycle verifier. It needs a state machine over
    capturable/refundable amounts, deadlines, both deployment sets, and the
    `PaymentAuthorized`/`Captured`/`Voided`/`Refunded`/`Reclaimed`/`Charged`
    events.
  - Until that exists, keep the escrow model away from auth-capture addresses so
    it does not raise false CRITICALs.
  - Bump the psv pin after a psv release.
- **X402testwebside:**
  - Bump the `x402-conformance` pin after the fix release, and with it the
    frontend catalog mirror and the check counts.
  - Handle `settlement_pending` explicitly: keep the tx hash, which the verifier
    currently discards; retry once; then reconcile.
  - Bump the psv pin.
  - Users of the hosted checks currently see the DI-001/002 false FAILs.

## Deliberately not done

- **auth-capture lifecycle checks in the suite.** That is a scheme
  implementation. rvf is the right home.
- **Lightning and Cardano active checks.** They need wallets and funded test
  rails. Matrix rows only.
- **Proving `upfront` ordering.** Unchanged since August (BACKLOG-017).
- **Grading inline-literal error codes** (Hedera, Aptos and others). This needs
  a different extractor. Recorded as a known gap.

## Decisions (confirmed by Mario, 2026-10-06)

The seven open questions of the draft, plus the pin, were decided as follows. All
eight are confirmed, not provisional.

1. **Registry boundary.** Role-scoped `/client/` and `/server/` declaring files are
   excluded from the facilitator-returnable registry, including the 23 go
   auth-capture `server/errors.go` codes.
2. **Retired codes.** The 17 codes upstream stopped declaring stay accepted as
   *retired* for six months; the recorded removal date is **2027-04-06**
   (`RETIRED_UNTIL`). The drift job fails after it.
3. **Cardano blind spot.** The TypeScript declaration pattern is widened to `ERR_\w+`.
4. **`deposit_below_min_deposit`.** Not accepted from a facilitator: the code
   (`invalid_batch_settlement_evm_deposit_below_min_deposit`) is excluded by name.
5. **Numeric `lastUpdated`.** Advisory (a PASS detail starting `advisory:`), not a
   FAIL; an ISO 8601 string is a plain PASS.
6. **Pending settle.** Reported as inconclusive through a new per-check reason code
   `settlement_pending` (exit 2). No new status.
7. **`paymentFlow` contradiction.** An upstream issue is drafted for Mario's review
   and has not been posted; RS-PR-026 stays advisory until upstream reconciles the two.
8. **Pin.** `.github/upstream-reviewed-commit` moves to `cb0ec5b` now, without
   waiting for #3577/#3622 to be released.

**Overlap between decisions 1 and 2, implemented literally.** Sixteen of the 17
retired codes (`invalid_exact_evm_server_*`, `invalid_upto_evm_server_*`) were
declared in `/server/` files, which decision 1 would exclude anyway. They are kept
in `RETIRED_ERROR_CODES` because decision 2 covers all 17 removals; only
`invalid_exact_solana_payload_amount_insufficient` is a facilitator code that
deployed Go facilitators will keep returning. If that overlap is not wanted, the 16
can be dropped from the retired set without touching anything else. Separately,
decision 1 removes **40** client/server codes that were accepted before this
review (the draft's 41 counted one that is also declared in a facilitator file and
therefore stays); they are excluded outright, not retired, because they were never
facilitator wire codes.

## What shipped

Check count 76 → **81** (FA-SET-004, RS-PR-027, RS-HS-009, FA-EXT-001,
RS-NEG-016). `reportVersion` 1.3 → **1.4** (the `settlement_pending` reason code).

| § | Change | Notes and deviations from the proposal |
|---|---|---|
| 1 | DI-001/002 and `DiscoveryItem.lastUpdated` accept ISO 8601 strings; a number is advisory | Strings that are not ISO 8601 still fail. Fixtures for both shapes plus a CDP-shaped item |
| 2 | `SettlementResponse` admits a failed answer with a hash (`is_pending`); FA-SET-001/003 retry a pending answer once with the same payload; FA-SET-004 (MINOR); RS-PAY-001/002 pending → SKIP `settlement_pending`; RS-NEG fails a rejection that carries a hash | **Deviation:** the model does not *require* a hash on `settlement_pending`; FA-SET-004 and RS-PAY-002 grade that instead, so the finding names the rule rather than surfacing as "invalid response". **Deviation:** FA-SET-002 still fails *any* hash on the underpaying payload, pending or reverted: that authorization must never be broadcast, which is the point of the check. A retry with a different hash fails FA-SET-003 (re-broadcast) |
| 3 | RS-PR-019 vocabulary keyed on (scheme, CAIP-2 namespace) for the eleven listed bindings; RS-PR-017 remediation names all four schemes | Fails only keys another binding defines; unknown keys and bindings without a vocabulary are not graded |
| 4 | RS-PR-026 scheme-aware and still advisory | SVM batch-settlement / EVM upto / EVM batch-settlement are never candidates; SVM upto and auth-capture always are; `autoCapture` dropped as a signal |
| 5 | RS-SEC-012 absolute-form request-target variant | Sent through the normal client with httpcore's `target` request extension rather than a hand-rolled socket: same bytes in the request line, over HTTP and TLS, and it runs through the injectable transport like every other variant. A real-socket test confirms the request line. Asterisk/authority form not added |
| 6 | Registry regenerated: **493 codes from 29 files** (+206/−57 against 344) | Decisions 1–4. Known gaps documented in the generator: inline literals (Hedera, Aptos, Keeta, XRPL, Stellar, Concordium, NEAR) and SVM batch prefix concatenation |
| 7 | RS-PR-027 (MAJOR for the MUSTs, advisory for the `exact` SHOULD); `choose_eip3009_requirement` prefers `authorization` over `upfront` and skips undefined flows; RS-PR-018 groups by the reserved keys too | `captureMode` MUST be `deferred` on collect-only routes and Starknet's `assetTransferMethod` MUST be `default`: not graded |
| 8 | RS-HS-009 (pay group, MAJOR) on the 402 and the paid response; FA-EXT-001 (MINOR) on `/verify`; `VerifyResponse.extensions` fixture | FA-EXT-001 does not grade `/settle` answers (the settle group runs after the registry) |
| 9 | RS-NEG-016 (active, MAJOR, only when builder-code is declared) | The unfunded probe signer makes a forwarding server visible: the facilitator's `insufficient_funds` instead of `extension_echo_mismatch` fails. A reasonless 402 passes with a note |
| 10 | auth-capture v1.1 declaration rules live in RS-PR-027 and RS-PR-026 | Lifecycle stays out of the suite (rvf) |
| 11 | Support matrix rows for Lightning, Cardano, Hedera, SVM batch-settlement, SVM upto delegated, Casper note | Lightning and Cardano are passive-only: the challenge is graded, nothing is paid |
| — | Pin `cb0ec5b`; support matrix "Latest upstream review" 2026-10-06 | The official drift test passes live against the clone at the pin (56 passed, 0 skipped) |

## Follow-ups (not in this change)

- **Sibling repos** (separate changes): psv (pending outcome, pending/auto-recovery
  scenario, §12 citations), rvf (auth-capture lifecycle verifier; keep the escrow
  model off auth-capture addresses), X402testwebside (pin, catalog mirror and counts,
  explicit `settlement_pending` handling).
- **Release:** v0.7.0 (new checks), including the catalog heading bump.
- FA-EXT-001 on `/settle` answers; asterisk-form and authority-form request targets.
- RS-PR-027: `captureMode` on collect-only routes; Starknet `assetTransferMethod`.
- §13 default-asset testnets in the safety allowlist (could).
- §14: re-run the FA-SVM tampers against Go's smart-wallet path.
- The registry's inline-literal and prefix-concatenation gaps need a different
  extractor.
- `RETIRED_ERROR_CODES` removal on or after 2027-04-06.
- Post the drafted upstream issue if Mario approves it.

## Open questions (as reviewed)

The questions below were the draft's; see [Decisions](#decisions-confirmed-by-mario-2026-10-06)
for the answers.

1. Registry boundary: should role-scoped `/client/` and `/server/` files be
   excluded? That is 92 codes, 41 of them already accepted today.
2. Retired codes: should they be kept as accepted, and if so, for how long?
3. Should `deposit_below_min_deposit` be accepted on a facilitator response or
   flagged? The spec says it is server-only.
4. Should a numeric `lastUpdated` be an advisory or silently accepted?
5. Should the pending outcome be `INCONCLUSIVE`, or is a new status warranted?
6. Should the CORE-vs-binding `paymentFlow` contradiction, which now covers both
   SVM `upto` and auth-capture, be raised upstream?
7. Should we pin to `cb0ec5b`, or wait for the next release so that #3577 and
   #3622 are in published packages?
