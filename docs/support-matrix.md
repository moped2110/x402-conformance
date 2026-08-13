# Support matrix

This matrix defines what an `x402-conformance` verdict actually assesses. A clean
run is conformance for the rows marked **supported**, not a blanket certificate for
every x402 transport, network, scheme, or transfer mechanism.

**Tool spec baseline:** `x402-foundation/x402@d454eb9` (2026-06-08)
**Latest upstream review:** `main@f62a9fa` (2026-08-13), rechecked 2026-08-13
**Review notes:** [`docs/upstream-review-2026-08.md`](upstream-review-2026-08.md)
**Review sources:** [upstream commits](https://github.com/x402-foundation/x402/commits/main/),
[V2 core specification](https://github.com/x402-foundation/x402/blob/main/specs/x402-specification-v2.md),
[scheme specifications](https://github.com/x402-foundation/x402/tree/main/specs/schemes), and
[Bazaar extension](https://github.com/x402-foundation/x402/blob/main/specs/extensions/bazaar.md).

**Review cadence: at most two weeks.** This is a commitment about the matrix, not a
chore. Between 2026-07-23 and 2026-08-13 the pin sat unreviewed for three weeks and
accumulated **two false positives** — RS-PR-019 and RS-PR-017 began failing conformant
endpoints after upstream rewrote CORE §6, and one of those checks was three weeks old
at the time. FA-ERR-001 was rejecting valid facilitator error codes over the same
window. Neither was findable by any test we own; only by reading upstream.

That asymmetry is the reason for the interval. A missing check costs us a sale. A check
that fails a conformant endpoint costs the customer an afternoon and costs us the claim
this document makes. Upstream shipped five fixes of one bug class in five weeks, so the
matrix goes stale faster than a monthly rhythm can track. The supply-chain workflow
already reports pin drift on a schedule; this row says what that report obliges.

Status meanings:

- **supported** — the relevant behavior has runnable checks and contributes to the verdict.
- **passive-only** — the shared HTTP envelope can be inspected, but mechanism-specific
  signing, verification, or settlement is not assessed.
- **planned** — explicitly not shipped; a clean run makes no claim about it.
- **out of scope** — intentionally excluded from this black-box suite.

## Transport and protocol

| Area | Status | Assessed behavior / boundary |
|---|---|---|
| HTTP x402 V2 | supported | 402 signaling, strict `PaymentRequired`, resource identity, headers, robustness, reports, facilitator, and Bazaar discovery checks. The challenge is also assessed as JSON *text*: literals RFC 8259 does not define and duplicate object keys are findings, because both make a challenge mean different things to different parsers. The selected HTTP method is never changed implicitly. |
| Payment flow models (CORE §6.1) | partially supported | `extra.paymentFlow` is graded against the defined set (RS-PR-025), and an escrow-shaped entry that does not declare its flow is flagged advisorily (RS-PR-026). What is **not** assessed is whether the endpoint actually runs the ordering it declares — proving that `upfront` settled before the handler ran, or that `escrow` settled twice, needs funded settlement on both sides of the resource. `extra.assetTransferMethod` and `extra.paymentFlow` are treated as protocol-reserved on every scheme, never as scheme-private keys. |
| HTTP x402 V1 | passive-only | Recognized and reported as V1; exit 2 (`INCONCLUSIVE`) for a V2 assessment. |
| x402 **over** MCP or A2A | out of scope | No transport adapter and no verdict: an endpoint that speaks x402 over MCP is not something this suite can assess. Not to be confused with *Interfaces* below — this row is about what gets tested, that section is about how the suite is driven. |
| `jp402` / `x-jp402` metadata | passive-only | Optional structural and arithmetic validation; not tax, legal, or invoice-compliance advice. |
| Bazaar discovery | supported | Strict response/pagination/filter checks. Cross-fetch is public-address-only by default with DNS pinning, redirect revalidation, caps, and explicit allowlists. A catalogued extension `schema` is scanned for `$ref`/`$id` values that are not same-document fragments (DI-004, x402#3039); the suite reports them and never resolves one, so inspecting a hostile catalogue cannot itself become the SSRF. |
| Builder-code | partially supported | The **server-declared** half is assessed: app-code format and the server staying within `MAX_SERVER_SERVICE_CODES` (RS-PR-023/024, x402#3027). The client and facilitator halves — echo rules for `a`, the combined-budget `extension_echo_mismatch` rejection, and the ERC-8021 CBOR calldata suffix — are **not** assessed: the first two need a payment the client controls, the third needs the settlement transaction. |
| Other extension payloads | passive-only | Unknown extension data is preserved; semantic correctness is not assessed. |

## Interfaces (how the suite is driven)

Two interfaces reach the same checks. They differ in what they can be asked to do,
because they differ in who is asking.

| Interface | Status | Scope and boundary |
|---|---|---|
| CLI (`x402-conformance`) | supported | The full surface. Transactional modes (`--pay`, `facilitator --settle`) exist here and require an explicit flag per run, per SECURITY.md. |
| MCP server (`x402-conformance-mcp`, `[mcp]` extra) | supported, passive only | Exposes `check_endpoint`, `check_discovery`, `explain_check` and `diff_reports`. It cannot sign, settle, or probe `/verify`: the tools take no signer key, no RPC URL and no `active` flag, and the module never imports the signing path. That is structural, not a default — an agent deciding for itself to sign is precisely the case SECURITY.md's per-run flag rule exists to prevent. |

**Destination policy on the MCP server.** `check_endpoint` and `check_discovery` take a
URL from the caller, so how far they reach depends on the transport. On `stdio` the
caller has exactly the reach of the person who started the server, and local addresses
are fetched — that is the intended use, testing an endpoint you are building. On the
shared transports (`sse`, `streamable-http`) only publicly routable destinations are
fetched, using the same address policy as the Bazaar cross-fetch; otherwise the server
would be a way to reach networks the caller cannot reach itself. The transport is the
operator's choice at start-up and is never a tool parameter.

## Schemes, networks, and transfer methods

| Scheme / mechanism | Network family | Status | Scope |
|---|---|---|---|
| `exact` / EIP-3009 | EVM (`eip155`) | supported | Active negative checks and exact on-chain Transfer proof. Signing is limited to local chains `1337`/`31337`, Base Sepolia `84532`, and Ethereum Sepolia `11155111`. |
| `exact` / EIP-3009 | EVM mainnets or unknown chains | out of scope | The safety policy rejects the run before payload construction; there is no override. |
| `exact` / Permit2 or EIP-2612 gas sponsoring | EVM | planned | No allowance, witness-recipient, deadline, or settlement semantics are claimed. |
| `exact` / ERC-7710 | EVM | planned | No delegation, manager, gas-limit, or simulation semantics are claimed. |
| `exact` | SVM (`solana`) | passive-only | CAIP-2 parsing, ATA derivation, a partial-transaction builder, and tamper primitives exist; no runnable conformance group or settlement verifier exists yet. Reviewed 2026-08-07 against the x402#2937 spec change: `extra.recentBlockhash` is a *construction hint* only, `extra.lastValidBlockHeight` is informational and may be ignored, and verification must **not** compare the transaction's blockhash with the hint. The FA-SVM tamper set contains no blockhash case, so nothing here would false-FAIL — checked rather than assumed. |
| `exact` | Starknet (`starknet:SN_MAIN`, `starknet:SN_SEPOLIA`) | planned | Spec landed 2026-08 (x402#2849) and is detailed enough to implement against: SNIP-9 OutsideExecution, SNIP-12 typed-data hashing, SNIP-6 `is_valid_signature`, `Caller` bound to `extra.feePayer`, single-`transfer` calldata, and mandatory settlement simulation. Nothing is implemented; a clean run makes no Starknet claim. |
| `exact` | Canton | planned | Spec landed 2026-08 (x402#2634). Nothing implemented; a clean run makes no Canton claim. |
| `exact` | XRPL, Near, Casper, Hedera, Aptos, AVM, Stellar, TVM, Keeta, and other families | passive-only | Shared V2 HTTP/wire checks only; no family-specific payload or on-chain proof. |
| `upto` | any | planned | No ceiling, metered-amount, replay, or actual-transfer checks. The *flow declaration* is graded (RS-PR-025/026) and `assetTransferMethod` is accepted on `upto` entries, but that is the challenge only. SVM `upto` defaults to the `escrow` flow (x402#3094/#3135) and settles twice around the resource; none of that ordering is verified. |
| `auth-capture` | any | planned | Recognised as a protocol-named scheme (RS-PR-017) so an endpoint offering it is not called unpayable, and its `extra.autoCapture` counts as a pre-handler signal for RS-PR-026. No authorize/capture/void/refund/reclaim semantics are assessed. |
| `batch-settlement` | any | planned | No escrow, voucher, aggregation, or redemption checks. |

## Facilitator completeness

| Capability | Status | Notes |
|---|---|---|
| `/supported` strict wire/schema behavior | supported | Invalid types and malformed advertised kinds fail closed. |
| Invalid `/verify` rejection and error reasons | supported | Uses signed semantic negatives; transport and malformed responses cannot become PASS. |
| Valid `/verify` returns true with balance semantics (`FA-VER-001`) | planned | Explicit catalog row; not hidden behind another ID. |
| `/verify` proves no state change (`FA-VER-005`) | planned | Requires a faithful funded-chain proof design. |
| `/settle` response and replay behavior | supported | Opt-in, testnet/local only. With RPC, success passes only after the exact token Transfer is proven; without proof it SKIPs. |

## Backlog decisions

The former open-ended backlog is normalized here so unsupported work cannot be
mistaken for a release defect or shipped coverage.

| Audit backlog | Decision |
|---|---|
| BACKLOG-001 Permit2 | planned; next EVM mechanism only after a mechanism abstraction and allowance/witness threat model. |
| BACKLOG-002 ERC-7710 | planned; implement only with delegation simulation and malicious-manager cases. |
| BACKLOG-003 runnable SVM | planned; requires local validator calibration and the same fail-closed testnet policy. |
| BACKLOG-004 `upto` | planned; requires actual metered-transfer proof. |
| BACKLOG-005 batch settlement | planned; adoption review before implementation. |
| BACKLOG-006 grant-before-settle | planned; funded testnet-safe design required. |
| BACKLOG-007 facilitator completeness | planned as `FA-VER-001` and `FA-VER-005`. |
| BACKLOG-008 calibration breadth | planned; add Node/Hono and another public-testnet strategy without mainnet settlement. |
| BACKLOG-009 networks/builder-code | Server-declared builder-code now ships (RS-PR-023/024). The client/facilitator halves and every unimplemented network stay passive-only pending mechanism-specific work; names alone never count as support. |
| BACKLOG-014 Starknet `exact` | planned; needs a Starknet signer, SNIP-12 typed-data reconstruction, and the same fail-closed testnet policy before any active check. |
| BACKLOG-016 Canton `exact` | planned; spec-only upstream, no signer or ledger binding here. |
| BACKLOG-017 payment-flow ordering | planned; RS-PR-025/026 grade the declaration. Proving an `upfront` settle really preceded the handler, or that `escrow` settled on both sides, needs funded settlement and a resource whose execution we can observe. |
| BACKLOG-015 active Bazaar `$ref` rejection | planned; DI-004 grades a catalogue passively. Posting a hostile registration to prove the facilitator *rejects* it needs a write surface, which is outside this black-box boundary. |
| BACKLOG-010 German guide/website integration | deferred to the product/documentation repositories; report and diff formats are ready for consumption. |
| BACKLOG-011 responsible disclosure | operational task; revalidate current versions and follow each target's policy before contact. Never scan third parties without authorization. |
| BACKLOG-012 real jp402 fixture | planned; current synthetic and captured fixtures remain structural-only. |
| BACKLOG-013 monitoring/EU VAT | deferred until an interoperable convention and demand exist; legal/tax review is required before launch. |

## Drift control

The weekly `Supply chain` workflow checks out upstream `main` and fails when it
moves beyond `.github/upstream-reviewed-commit`. The same job compares the live
upstream error-reason registry and runs the strict wire/report-schema tests. A
pin update therefore requires reviewing this matrix and the affected checks; it
must never be a blind commit-hash bump.

The error-registry comparison has **two** halves since 2026-08, and the reason is
worth recording. It originally watched only the `ErrorReasons` Zod enum, which was
then the single machine-enforced vocabulary. Upstream's package split froze that
enum under `legacy/` and moved new codes into the per-mechanism packages — so the
guard stayed green for months while the codes we accepted fell 300 behind the
codes conformant facilitators return, and FA-ERR-001 would have failed them. The
job now also regenerates `src/x402_conformance/error_registry.py` via
`tools/sync_error_registry.py` and diffs it. A guard pointed at a file upstream
has stopped changing reports success, not safety.

The registry deliberately stops at the wire. Upstream's route-validation reasons
(`unsupported_payment_flow`, `unsupported_asset_transfer_method`,
`missing_scheme`, `missing_facilitator`) look like error codes and are not: they
are `RouteValidationError` values raised when a resource server starts with a
misconfigured route, and they never appear in a `VerifyResponse` or
`SettleResponse`. Adding them would make FA-ERR-001 accept codes that must never
reach a client, so the generator does not collect them and this note exists so
nobody adds them by hand.
