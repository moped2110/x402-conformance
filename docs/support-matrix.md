# Support matrix

This matrix defines what an `x402-conformance` verdict actually assesses. A clean
run is conformance for the rows marked **supported**, not a blanket certificate for
every x402 transport, network, scheme, or transfer mechanism.

**Tool spec baseline:** `x402-foundation/x402@d454eb9` (2026-06-08)
**Latest upstream review:** `main@aad8e4e` (2026-07-17), rechecked 2026-07-18
**Review sources:** [upstream commits](https://github.com/x402-foundation/x402/commits/main/),
[V2 core specification](https://github.com/x402-foundation/x402/blob/main/specs/x402-specification-v2.md),
[scheme specifications](https://github.com/x402-foundation/x402/tree/main/specs/schemes), and
[Bazaar extension](https://github.com/x402-foundation/x402/blob/main/specs/extensions/bazaar.md).

Status meanings:

- **supported** — the relevant behavior has runnable checks and contributes to the verdict.
- **passive-only** — the shared HTTP envelope can be inspected, but mechanism-specific
  signing, verification, or settlement is not assessed.
- **planned** — explicitly not shipped; a clean run makes no claim about it.
- **out of scope** — intentionally excluded from this black-box suite.

## Transport and protocol

| Area | Status | Assessed behavior / boundary |
|---|---|---|
| HTTP x402 V2 | supported | 402 signaling, strict `PaymentRequired`, resource identity, headers, robustness, reports, facilitator, and Bazaar discovery checks. The selected HTTP method is never changed implicitly. |
| HTTP x402 V1 | passive-only | Recognized and reported as V1; exit 2 (`INCONCLUSIVE`) for a V2 assessment. |
| MCP and A2A transports | out of scope | No transport adapter or verdict. |
| `jp402` / `x-jp402` metadata | passive-only | Optional structural and arithmetic validation; not tax, legal, or invoice-compliance advice. |
| Bazaar discovery | supported | Strict response/pagination/filter checks. Cross-fetch is public-address-only by default with DNS pinning, redirect revalidation, caps, and explicit allowlists. |
| Builder-code and other extension payloads | passive-only | Unknown extension data is preserved; semantic correctness of builder-code arrays is not yet assessed. |

## Schemes, networks, and transfer methods

| Scheme / mechanism | Network family | Status | Scope |
|---|---|---|---|
| `exact` / EIP-3009 | EVM (`eip155`) | supported | Active negative checks and exact on-chain Transfer proof. Signing is limited to local chains `1337`/`31337`, Base Sepolia `84532`, and Ethereum Sepolia `11155111`. |
| `exact` / EIP-3009 | EVM mainnets or unknown chains | out of scope | The safety policy rejects the run before payload construction; there is no override. |
| `exact` / Permit2 or EIP-2612 gas sponsoring | EVM | planned | No allowance, witness-recipient, deadline, or settlement semantics are claimed. |
| `exact` / ERC-7710 | EVM | planned | No delegation, manager, gas-limit, or simulation semantics are claimed. |
| `exact` | SVM (`solana`) | passive-only | CAIP-2 parsing, ATA derivation, a partial-transaction builder, and tamper primitives exist; no runnable conformance group or settlement verifier exists yet. |
| `exact` | XRPL, Near, Casper, Hedera, Aptos, AVM, Stellar, TVM, Keeta, and other families | passive-only | Shared V2 HTTP/wire checks only; no family-specific payload or on-chain proof. |
| `upto` | any | planned | No ceiling, metered-amount, replay, or actual-transfer checks. |
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
| BACKLOG-009 networks/builder-code | passive-only pending mechanism-specific implementations; names alone never count as support. |
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
