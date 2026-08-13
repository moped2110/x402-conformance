# Upstream review — 2026-08-07 (`61349de..c7e0ac8`)

Review of `x402-foundation/x402` from the previously reviewed pin `61349de`
(2026-07-23) to `c7e0ac8` (2026-08-07): 37 commits, four security fixes, three
spec changes. This is the record of what was assessed, what shipped as a result,
and what was deliberately left out.

The weekly `Supply chain` drift job had been failing since 2026-07-20 — three
consecutive scheduled runs — which is the alarm working as designed.

## Summary

| # | Finding | Severity for us | Outcome |
|---|---|---|---|
| 1 | `KNOWN_ERROR_CODES` gates FA-ERR-001 on a vocabulary upstream froze | **Wrong verdict shipped** | Fixed |
| 2 | No check for paywall bypass by path re-encoding | **Missing critical coverage** | RS-SEC-012 |
| 3 | Bazaar `$ref`/`$id` SSRF is now normative | New coverage | DI-004 |
| 4 | builder-code grew real semantics | New coverage | RS-PR-023/024 |
| 5 | Paid 200 must not be shared-cacheable | New coverage | RS-HS-008 |
| 6 | Settle success without a `Transfer` event is now a failure | Already ahead | Matrix note + psv citation |
| 7 | SVM `recentBlockhash` is a non-binding hint | No action needed — verified | Matrix note |
| 8 | Starknet `exact` scheme published | Scope statement | Matrix row (planned) |
| 9 | Three new default-asset networks | Metadata | Celo Sepolia allowlisted |

## 1. FA-ERR-001 was failing conformant facilitators

The most serious finding, and not a coverage gap — a wrong verdict we were
already shipping.

`KNOWN_ERROR_CODES` gates FA-ERR-001: an `invalidReason` outside it is a FAIL. It
was vendored from the `ErrorReasons` Zod enum in
`typescript/packages/legacy/x402/src/types/verify/x402Specs.ts`. That was correct
once — the reference SDK ran `z.enum(ErrorReasons)` over every wire field, so
nothing else could appear.

Upstream's package split ended it. The file moved under `legacy/`, upstream
stopped extending it, and current mechanisms declare and return their own codes.
The gap measured **344 codes across 28 declaring files**. Every one of them was a
FAIL against an implementation doing nothing wrong.

The sharpest case is a spelling. The current EVM package returns
`invalid_exact_evm_authorization_value`; the frozen enum only ever contained
`invalid_exact_evm_payload_authorization_value`. Same condition, different string,
guaranteed FAIL.

**Why the drift guard did not catch it.** It compared our vendored set against
`x402Specs.ts` and that file never changed — it still has exactly 41 codes today.
The guard reported success for the entire period the accepted vocabulary was
falling behind, because it was watching a file upstream had abandoned. A drift
guard pointed at a frozen source measures nothing.

Fixed by generating instead of hand-maintaining:

- `tools/sync_error_registry.py` extracts wire codes from the per-language
  declaration sites, excluding tests (which assert on invalid codes by design).
- `src/x402_conformance/error_registry.py` is the generated, committed result,
  grouped by declaring file so a diff shows which mechanism moved.
- The drift test re-extracts from a live clone and diffs the module, naming the
  offending codes. One env var (`X402_UPSTREAM`) now enables both halves.

The two codes added in this window —
`invalid_exact_evm_transfer_event_mismatch` (x402#2385/#2727/#3032) and
`extension_echo_mismatch` (the builder-code echo rules) — are covered by this,
but they were never the interesting part.

## 2. RS-SEC-012 — paywall bypass by path re-encoding

Upstream fixed the same class three times in three weeks, in three languages:
x402#3036 (TypeScript), #3055 (Python), #3044 (Go). We had no check for any of
it. Upstream's own description of the Python case:

> The route then misses, `requires_payment()` returns False, and the middleware
> serves the protected resource with no payment verification or settlement.

That is the exact failure this suite exists to catch. RS-SEC-012 (CRITICAL,
passive, no signer) re-requests the protected URL under encodings a correct
server must still gate.

Two things only surfaced by building the reproduction before the check:

**The terminator needs two placements.** Python's `$` matches just before a
trailing newline, so a vulnerable Python route still matches `/x%0A` and only a
terminator with a character *after* it exposes the missing `re.DOTALL`.
JavaScript's `$` is strict, so the trailing form is what catches #3036. The first
draft probed only the trailing form — it would have passed every vulnerable
Python server while looking like coverage.

**The terminator must land in the wildcard tail.** Injecting it mid-path corrupts
the protected prefix, so the request misses the route as an unrelated URL instead
of exercising the matcher, and the probe silently proves nothing.

Against false positives, a control probe against a nonexistent sibling runs
alongside; if that is served too, the endpoint answers everything and the check
SKIPs with that reason instead of inventing a critical finding. Trailing slashes,
letter case and `;params` are excluded — they can legitimately address a
different resource, so a 2xx there proves nothing.

Verified in both directions against live servers, not only mocks: PASS against
`tools/calibration_target.py`, FAIL against a server carrying upstream's actual
pre-fix route regex, which serves its secret on `/data%0Aa` with HTTP 200.

## 3–5. New coverage from the spec changes

**DI-004** (MAJOR) — x402#3039 made it normative that Bazaar `$ref`/`$id` values
must be same-document fragments and that facilitators must not resolve external
ones. A validator's default resolver dereferences `http(s)`, `file` and relative
references while *compiling* the schema, before the instance is ever checked, and
the schema is client-supplied. `discovery.py` had no notion of `$ref`. The check
reads and reports; it never dereferences, since doing so is the request the spec
forbids and would aim our traffic wherever the entry points. A test asserts we
don't.

**RS-PR-023 / RS-PR-024** (MINOR) — builder-code was format-only when the matrix
last called it passive-only. x402#3027 and #2994 added per-party service-code
reservations (client 5 / server 5 / facilitator 1) that exist so no participant
can crowd out another. The server-declared half is visible in the challenge, so
it is checkable now. This moves BACKLOG-009 partway.

**RS-HS-008** (MINOR) — RS-HS-007 covered the 402; nothing covered the 200
carrying content the client just paid for, which a shared cache will store and
serve to someone who did not pay. x402#2990 made `private` the default there.

## 6. Transfer-event verification — we were already ahead

x402#2385 (TS), #2727 (Go) and #3032 (Python) stopped treating `receipt.status`
as proof of transfer:

> The receipt's status only tells us the tx did not revert; it does not tell us
> that the expected ERC-20 Transfer was emitted from the expected token contract
> with the expected (from, to, value).

FA-SET already proves the exact token `Transfer` when an RPC is supplied, and
SKIPs rather than passing without it. No change needed.

It is worth recording where this lands for the sibling repos: psv's SC1 scenario
(event/ABI drift producing silent loss) is precisely this bug class, and upstream
fixing it in all three SDKs is the strongest available evidence that SC1 models a
real failure rather than a hypothetical.

## 7. SVM `recentBlockhash` — checked, no action

The x402#2937 spec change makes `extra.recentBlockhash` a construction *hint*:
`lastValidBlockHeight` is informational and may be ignored, and verification must
**not** compare the transaction's blockhash against the hint. A tamper case
asserting the opposite would now be a false FAIL. The FA-SVM tamper set was
inspected and contains no blockhash case, so nothing changes — recorded because
"we checked and it was fine" is a different statement from "we didn't look".

## 8–9. Scope and metadata

**Starknet** (x402#2849) — a 377-line `exact` scheme spec. Nothing is
implemented; the matrix gains an explicit `planned` row so the absence is stated
rather than silent, plus BACKLOG-014.

**New default assets** — Flare mainnet (14, x402#3031), Celo mainnet (42220) and
Celo Sepolia (11142220, both x402#3025). Only Celo Sepolia enters
`_ALLOWED_EVM_NETWORKS`: the safety policy rejects mainnets before payload
construction and has no override, so listing the other two would be misleading.

## Deliberately not done

- **Active Bazaar `$ref` rejection.** Posting a hostile registration to prove a
  facilitator rejects it needs a write surface, outside this black-box boundary.
  BACKLOG-015.
- **Client/facilitator builder-code halves.** The echo rules and the combined
  budget `extension_echo_mismatch` need a payment the client controls; the
  ERC-8021 CBOR calldata suffix needs the settlement transaction.
- **Starknet checks.** Needs a Starknet signer and SNIP-12 typed-data
  reconstruction. BACKLOG-014.
- **Celo/Flare mainnet signing.** Excluded by the safety policy, by design.

---

# Upstream review — 2026-08-13 (`c7e0ac8..f62a9fac`)

Second window, six days and 19 commits later. The drift job was green when this
started, so nothing was overdue; the review is what turned it up.

## Summary

| # | Finding | Severity for us | Outcome |
|---|---|---|---|
| 1 | CORE §6.1 rewrite makes two of our checks fail conformant endpoints | **Wrong verdict shipped** | Fixed |
| 2 | `auth-capture` was never in our scheme set | **Wrong verdict shipped** | Fixed |
| 3 | Backslash bypass (x402#3116) not covered by RS-SEC-012 | Missing critical coverage | Two variants |
| 4 | Two RS-SEC-012 variants never left the client | **Silent non-coverage** | Fixed + guard |
| 5 | `paymentFlow` is a new gradeable field | New coverage | RS-PR-025/026 |
| 6 | Upstream contradicts itself on when `paymentFlow` is required | Cannot grade | Advisory + recorded |
| 7 | Canton `exact`, SVM `upto` escrow | Scope statement | Matrix rows |
| 8 | Error registry unchanged; config reasons are not wire codes | Verified, no action | Boundary documented |

## 1–2. The §6.1 rewrite produced two wrong verdicts

`specs/x402-specification-v2.md` §6 was rewritten around **payment flow models**:
`authorization` (verify → resource → settle), `upfront` (settle → resource), and
`escrow` (settle → resource → settle). Two consequences landed on us.

**`assetTransferMethod` is no longer scheme-private.** §6.1:

> `extra.assetTransferMethod` and `extra.paymentFlow` are protocol-reserved keys
> in `PaymentRequirements.extra`: clients and servers MUST interpret them as
> defined here rather than as opaque scheme-private fields.

RS-PR-019 treated it as an `exact`-only discriminator and failed any `upto` entry
carrying it. The spec now names `upto` in the very sentence explaining the key's
purpose. Both reserved keys are excluded from every scheme vocabulary; the `upto`
branch grades the real `exact` vocabulary instead, so the check keeps its teeth.

**`auth-capture` is the fourth named scheme.** RS-PR-017 called it unpayable.
It has `specs/schemes/auth-capture/`, an EVM binding, and `"scheme":
"auth-capture"` on the wire. §6 now lists it explicitly. This one had been wrong
since before the previous review — the directory already existed at `c7e0ac8`;
only the core spec's prose caught up.

Both are the same class as the FA-ERR-001 finding in the first window, from the
other direction: there our guard had gone stale, here the spec moved under a
check that was correct when written.

## 3–4. RS-SEC-012, one week old, was both incomplete and partly inert

**x402#3116** is a bypass the variant set missed. `normalizePath` folded every
`\` to `/` after decoding, so a backslash split the middleware's view of the path
while the router still dispatched to the protected handler — "the paywall failed
open onto the paid handler with nothing settled". Reachable in two forms, because
adapters decode different amounts before the middleware runs: raw on Express,
`%5C` on Hono. Both are now probed.

**The worse half was ours.** The dot-segment variants were sent literally
(`/./x`, `/a/../x`). RFC 3986 §5.2.4 requires the *client* to remove dot
segments, and httpx does — so those two probes had been re-sending the canonical
protected path since the day they were written. They saw the baseline's 402 every
time and passed every time: two of nine variants were coverage on paper and
nothing on the wire.

Percent-encoded, they survive the client and ask the sharper question anyway —
whether the server decodes before it normalises, the same ordering mistake as the
backslash and separator bugs. `test_no_variant_is_inert_on_the_wire` now holds
the whole set to that rule, so the next variant that cannot leave the client
fails the build instead of looking like a passing check.

x402#3073 (ts/py path normalization) and x402#3100 (Go wildcards with `(?s)`) add
no variant but confirm the class in a third and fourth implementation. Five fixes
across four languages in five weeks; this is not settling down.

## 5–6. Payment-flow checks, and a contradiction we will not adjudicate

**RS-PR-025** (MAJOR) grades `extra.paymentFlow` against the defined set. §6.1
says a client MUST NOT construct a payment for a flow it does not recognize and
SHOULD skip the entry, so an invented value is not cosmetic — it makes the entry
unpayable by every conformant client.

**RS-PR-026** is advisory and stays advisory, because upstream currently says
both things:

- CORE §6.1: "When the resolved payment flow is not `authorization`,
  `PaymentRequired` `accepts[].extra.paymentFlow` MUST be present so clients can
  reason about pre-handler fund commitment without scheme-specific knowledge."
- `scheme_upto_svm.md`, on the same field: "Only supported value is `escrow`;
  omit to use that default."

An SVM `upto` endpoint that omits the field is correct by its scheme binding and
in violation of the core spec. Failing it would be punishing an implementer for
choosing one half of an upstream contradiction, so the check reports and never
gates. Worth raising upstream; until then the disagreement is recorded rather
than resolved by us.

## 7–8. Scope and the registry boundary

**Canton `exact`** (x402#2634) gets a `planned` matrix row and BACKLOG-016.
**SVM `upto`** (x402#3094/#3135) defaults to the `escrow` flow and settles twice
around the resource; the matrix now says the declaration is graded and the
ordering is not (BACKLOG-017).

**The error registry is unchanged at 344 codes** across all 19 commits —
`sync_error_registry --check` is clean against `f62a9fac`.

One near-miss worth recording. The new `unsupported_payment_flow` and
`unsupported_asset_transfer_method` look exactly like wire codes. They are
`RouteValidationError` values raised when a resource server starts with a route it
cannot serve, and they never appear on a `VerifyResponse` or `SettleResponse`.
The generator misses them only because they are inline literals rather than
exported constants — luck, not design. Adding them would make FA-ERR-001 accept
codes that must never reach a client, so the boundary is now written into
`tools/sync_error_registry.py` where the next person to widen a pattern will read
it.

## Deliberately not done

- **Payment-flow ordering.** Proving an `upfront` settle really preceded the
  handler, or that `escrow` settled on both sides, needs funded settlement and an
  observable resource execution. BACKLOG-017.
- **Canton checks.** Spec-only upstream. BACKLOG-016.
- **`auth-capture` semantics.** Recognised as payable so we stop failing it;
  authorize/capture/void/refund/reclaim is a scheme implementation, not a matrix
  row.
