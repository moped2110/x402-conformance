# Threat-Model Mapping — published x402 attacks ↔ conformance checks

Traceability from the public x402 security literature to this suite's checks. Purpose: (1)
show which published attack classes the suite already exercises, (2) surface the gaps as
concrete check candidates, and (3) record where system-level verification (the companion
`psv` project) covers ground the black-box suite cannot.

**Sources (verify before citing in outreach):**
- **P1** — Li, Wang, Wang, *Five Attacks on x402 Agentic Payment Protocol*, arXiv:2605.11781 (2026-05-12). Testbed on local chains, Base Sepolia, and live endpoints; audit of 3 open-source SDKs + 4 live endpoints → 11 vulnerabilities across 5 classes.
- **P2** — *Free-Riding in the AI Economy: Demystifying Logic Flaws in x402-Enabled Payment Systems*, arXiv:2605.30998. Invariant-centric: I1 payment-integrity (sync gap), I3 context-binding (cross-resource substitution), I4 authorization-uniqueness (service duplication).
- **P3** — *A402: Binding Cryptocurrency Payments to Service Execution for Agentic Commerce*, arXiv:2603.01179 (mitigation: bind payment to execution).

This is a black-box conformance suite: it can only observe an endpoint's externally visible
behaviour. Some attacks (e.g. Sybil flooding, caller-unbound settlement) are partly or wholly
outside single-endpoint black-box scope; those are marked accordingly rather than papered over.

---

## Mapping table

| Paper attack | What it is | Our check(s) | Status | Verdict |
|---|---|---|---|---|
| **P1 I-A** Revert-grant under optimistic execution | Server grants the resource before on-chain finality; if settlement later fails/reverts → unpaid service. (P2 **I1** sync gap.) | RS-NEG-010 (unfunded payer → resource not delivered before settlement); catalog Open-Q #1 (serve-before-settle ordering) | RS-NEG-010 **planned**; ordering flag **undecided** | **Partial gap** → build RS-NEG-010; deeper case (grant valid at settle but undone by reorg) is `psv` finality terrain |
| **P1 I-B** Unauthorized settlement preemption | Caller-unbound Permit2 `settle()` lets an observer consume the authorization before the legitimate facilitator → payment without service | — (eip3009 path is caller-agnostic by construction; Permit2/proxy settle path not modelled) | **not covered** | **Scope note** — Permit2-path caller-binding; facilitator-design issue, `psv`/settlement terrain |
| **P1 II** Replay / idempotency across the HTTP–chain boundary | A reusable `X-PAYMENT` payload yields multiple HTTP grants when the server doesn't atomically record payment identity before releasing. (P2 **I4** service duplication.) | RS-SEC-001 (replay after settlement), RS-SEC-002 (parallel race → exactly one), FA-SET-003 (double-settle nonce) | **shipped** | **Covered** — strongest area |
| **P1 II / P2 I3** Missing resource-identifier binding | A valid payment for resource A is accepted at resource B (payment not bound to the requested resource) | RS-SEC-003 (cross-resource replay) | **planned**, currently marked "redundant with RS-NEG-007+RS-SEC-001" | **Gap** → P1/P2 are direct evidence it is a *distinct* audited vuln; **un-defer and implement** |
| **P1 III** Cache leakage | Paywalled 402/response cacheable → CDN/proxy serves protected content or a stale paywall | RS-HS-007 (402 not cacheable: `no-store`/`private`) | **shipped** | **Covered** |
| **P1 III** Header ambiguity | Simultaneous v1 + v2 payment headers → deployment-dependent parser confusion | RS-SEC-006 (header smuggling / precedence); RS-HS-005 (legacy v1 header absent) | RS-SEC-006 **planned/deferred**; RS-HS-005 **shipped** | **Partial gap** → build RS-SEC-006 (needs a second-header primitive in `active.py`) |
| **P1 IV** Server-selection: metadata manipulation | Bazaar listing advertises terms that differ from the resource's live 402 (bias agent toward a malicious/cheaper-looking endpoint) | DI-003 (listed `accepts` vs live 402 staleness) | **planned/deferred** | **Gap** → build DI-003; catches lying listings |
| **P1 IV** Server-selection: Sybil flooding | Adversary floods discovery with sock-puppet listings | — | **not covered** | **Out of scope** — needs cross-endpoint/network trust analysis, not single-endpoint black-box |

---

## Concrete follow-ups this mapping produces

Ranked by leverage (all money-invariant-safe; passive or testnet-only):

1. **RS-SEC-003 — resource-identifier binding (un-defer).** Both P1 and P2 audit "missing
   resource-id binding" as a real, distinct vulnerability. Our catalog currently deprecates it
   as redundant; the literature says otherwise. Implement: take a valid payment built for
   resource A's requirements and present it at resource B; assert rejection. Highest-value gap.
2. **RS-NEG-010 — unfunded-payer / grant-before-settle.** Present a well-formed payment from a
   zero-balance payer; assert the resource is **not** delivered before settlement is confirmed.
   The black-box shadow of P1 I-A / P2 I1.
3. **RS-SEC-006 — header ambiguity/precedence.** Send contradictory v1+v2 payment headers;
   assert deterministic, documented precedence. Needs a second-header primitive in `active.py`
   (today `ActiveContext` sets only `PAYMENT-SIGNATURE`).
4. **DI-003 — listing-vs-live staleness.** Cross-fetch each listed resource's live 402 and
   compare `accepts`; a mismatch is metadata manipulation (P1 IV) or plain staleness.

## Where we go *beyond* the papers (the differentiator)

P1–P3 concentrate on the synchronous HTTP↔settlement boundary. They treat the chain as a
finality oracle and largely stop at "grant before finality." The companion system-level project
(`psv`) covers ground none of the three papers test in depth:

- **Reorg / finality depth** — a grant that is valid at settlement time but undone by a chain
  reorganisation. P1 I-A names "before finality"; `psv` actually drives reorgs against a
  controlled chain and measures the divergence.
- **Reconciliation** — chain-truth vs. server-ledger divergence tracked over time
  (`SILENT_LOSS` / `PHANTOM_CREDIT`), the persistent form of P2's integrity invariant.
- **Token quirks** — fee-on-transfer (credited amount ≠ authorized amount) and the
  EOA-asset silent no-op (already shipped here as RS-NEG-015 / FA-VER-003, tracking x402#2554).

**Positioning for disclosure/outreach:** re-reporting the papers' own 11 findings adds nothing.
The value is (a) a *reusable, reproducible* black-box runner for the classes they found by hand,
and (b) the finality/reconciliation/token-quirk surface they did not test. Any writeup should
lead with that delta, not with the known classes.

---

*Provenance: derived from the abstracts/structure of the cited arXiv papers (2026). Figures such
as P1's "248 grants/payment" and "RGP 5.18%" are the papers' own; re-verify against the source
PDF before quoting externally.*
