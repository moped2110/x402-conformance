# Integration of x402-Testcases.md — Analysis & Categorization

**Question:** How do we integrate these into x402-conformance?
**Short answer:** Only a part of them belongs in this tool. The larger part tests something else — and that is a good thing.

## The central distinction (please take seriously)
`x402-Testcases.md` is a test catalog for **building and operating an x402 payment system** — i.e., for a server/agent that accepts payments, settles on-chain, queries RPC nodes, maintains a database, and performs reconciliation.

**x402-conformance is something else:** a **black-box tester** that points to an x402 endpoint from the outside and checks whether its *protocol behavior* complies with the x402 V2 spec. We are an external client, not a payment backend. We have no RPC quorums, no DB, no reconciliation — and we should not have them.

**Consequence, plainly stated:** About 60–70% of the document is *principally not testable* with a black-box tester because it concerns the internal state of the system (DB locks, RPC failover, memory leaks, ABI drift). Pulling this into x402-conformance would dilute the tool and turn a sharp, focused utility into a multi-year platform project — out of scope here.

The disciplined path: harvest the ~20–30% black-box testable cases (some of which are real gaps we didn't have yet), and leave the rest to the appropriate tooling.

---

## 1. Harvest: What goes into x402-conformance?

### 1a) Confirmation of existing IDs
These upload cases correspond to existing catalog IDs — a nice confirmation that `conformance-catalog.md` is solid:
- **Test 1 / RS-PR-001:** `x402Version` check.
- **Test 3 / RS-NEG-008:** Expiration handling.
- **N2/N3 / RS-PR-013:** Address format/checksum.
- **N4 / RS-SEC-011:** Overflow robustness.
- **N22 / FA-SUP-002:** CAIP-2 network format.

### 1b) Genuinely NEW — Add as checks (the wins from the upload)
These six are black-box testable and we didn't have them yet. They move to `conformance-catalog.md`:

| ID | Origin | Test | Mode |
|----|--------|------|------|
| **RS-HS-007** | PR1 | 402 with payment details must not be cacheable → check `Cache-Control: no-store`/`private`, no `public`/long `max-age` | passive |
| **RS-PR-013** | N1/N2 | `payTo`/`asset` must match the CAIP-2 namespace of the `network` (no Solana address on `eip155`) | passive |
| **RS-PR-014** | N5 | `amount` must be > 0 (not "0", not negative) | passive |
| **RS-NEG-014** | N10 | Payment with well-formed but **wrong asset contract** → must be rejected (server checks contract address, not symbol) | active |
| **RS-SEC-010** | C0 | **Cross-Chain Signature Replay**: validly signed payload for network A against endpoint B with a different `chainId` → must be rejected (EIP-712 domain binds chainId) | active |
| **RS-SEC-011** | N4 | Near-2²⁵⁶ amount values in requirements or payload → no crash/overflow | active |

**C0 is well spotted:** the dangerous replay in x402 is not the classic network replay, but the on-chain signature replay across chains. The defense (EIP-712 domain separator with chainId) is exactly what RS-SEC-010 tests. Adopted.

---

## 2. Out of scope: Where the rest belongs

Valuable, but not for a black-box conformance tester. These categories belong to other kinds of tooling:

### → Payment observability / monitoring
Reconciliation (O1–O4, D3 — DB-vs-chain drift), Stuck Payment Detection (O2), RPC Quorum/Health (N20–N23, C10), Provider Inconsistency (D5), Audit Log Integrity (O3), Orphaned Settlements (O4). Visibility over payments, not conformance of an endpoint.

### → Paywall gateway / invoicing
Currency Mismatch/Slippage (PR5, T10), Refund Path (R6, G7), Multi-Recipient Split (PR6), Receipt Generation (R4), Fee Handling.

### → Policy engine
Agent Budget Loop (N24 — LLM in loop), Spend Limit (Test 6), Compromised Key/Anomalous Pattern (N25), Agent rejects (Test 5, N26/N27). Deterministic limits outside the LLM.

### → Compliance / legal
Sanctions Screening (R2), MiCA Stablecoin Status (R3), Geo-Fencing (R5) — to be reviewed by counsel. Not conformance.

---

## 3. Discarded: Out of scope

- **Part 6 Load/Stress Tests (ST1–ST11, S1–S6):** k6/Artillery + Anvil. Performance testing is its own discipline. At most a very late, separate module — explicitly not the conformance core.
- **Client/Wallet UX (U1–U7):** Browser extension conflicts, wallet popup timeouts, app resume. Behavior of the client, not the endpoint.
- **Supply Chain/Deploy (SC1–SC6):** ABI drift, library bumps, blue/green, config drift. This is the CI/CD concern of the *implementer* — a justified but internal discipline. (SC1 ABI drift is a top risk — rightly so, but not testable from the outside; a monitoring/observability signal can catch it indirectly.)
- **Token Quirk Internals (T1 USDT void return, T3 Internal Tx, T5 Fee-on-Transfer, T6 Rebase, T8 Permit2 Parsing, T9 Multicall):** This concerns *how a settlement backend recognizes payments* — server-internal. From a black-box perspective, we only see the advertised `asset` (covered by RS-PR).
- **Chain Settlement Depth (C1 Soft/Hard Finality, C4–C6 Confirmations, C9 Sequencer, Test 7/11/12 Reorg/RBF):** Requires access to the server's settlement logic. Out for black-box.

---

## Next Steps

1. **Immediate (this state):** Supplement six new checks (1b) in `conformance-catalog.md`. RS-NEG-014 and RS-SEC-010 are implemented in the course of T-01 (payload builder available); the passive RS-HS-007/RS-PR-013/-014 are immediately implementable.
2. **Consciously NOT do:** load/stress, UX, supply chain, settlement internals in x402-conformance. If at all, later as separate tools.
