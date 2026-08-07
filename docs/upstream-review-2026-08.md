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
