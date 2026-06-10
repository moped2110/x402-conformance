# x402 Conformance Test Catalog

**Spec baseline:** x402 Protocol v2 — repo `x402-foundation/x402`, commit `d454eb9` (2026-06-08)
**Documents referenced:**
- CORE = `specs/x402-specification-v2.md`
- HTTP = `specs/transports-v2/http.md`
- EVM = `specs/schemes/exact/scheme_exact_evm.md`

**Status:** Draft v0.1 (2026-06-09). Every test case carries a spec reference (traceability). Severity: **C**ritical (security/funds at risk), **M**ajor (spec violation, interop broken), **m**inor (robustness/quality).

**Target types:**
- **RS** = Resource Server (the x402-paywalled endpoint) — primary MVP target
- **FA** = Facilitator (`/verify`, `/settle`, `/supported`) — secondary target
- **DI** = Discovery/Bazaar endpoint — Phase 2

---

## 1. RS-HS — 402 Handshake (unpaid request)

| ID | Test | Expected | Spec ref | Sev |
|----|------|----------|----------|-----|
| RS-HS-001 | GET/POST without payment headers | Status 402 | HTTP §Payment Required Signaling | M |
| RS-HS-002 | 402 response carries `PAYMENT-REQUIRED` header | Header present | HTTP §Payment Required Signaling | M |
| RS-HS-003 | `PAYMENT-REQUIRED` header is valid base64 | Decodes cleanly | HTTP §Payment Required Signaling | M |
| RS-HS-004 | Decoded header is valid JSON matching `PaymentRequired` schema | Schema-valid | CORE §5.1 | M |
| RS-HS-005 | Legacy `X-*` headers absent in V2 responses (deprecated) | No `X-PAYMENT` etc.; flag if V1-only | HTTP §Header Summary | m |
| RS-HS-006 | Response body usable alongside 402 (no protocol data required in body) | Protocol info complete via headers alone | HTTP §Response Body | m |
| RS-HS-007 | 402 with payment details is not cacheable | `Cache-Control` is `no-store`/`private` (no `public`, no long `max-age`); else CDN/proxy could serve a stale paywall | RFC 9111 + PR1 (testcase-integration-analysis) | M |

## 2. RS-PR — PaymentRequired schema content

| ID | Test | Expected | Spec ref | Sev |
|----|------|----------|----------|-----|
| RS-PR-001 | `x402Version` present and `== 2` | Pass | CORE §5.1.2 | M |
| RS-PR-002 | `resource` object present with required `url` | Pass | CORE §5.1.2 | M |
| RS-PR-003 | `resource.url` matches the requested resource (no mismatch/spoofing) | Match | CORE §5.1.2 | M |
| RS-PR-004 | `accepts` array present, ≥1 entry | Pass | CORE §5.1.2 | M |
| RS-PR-005 | Each accepts entry: required fields `scheme`, `network`, `amount`, `asset`, `payTo`, `maxTimeoutSeconds` | All present | CORE §5.1.2 | M |
| RS-PR-006 | `network` is valid CAIP-2 (`namespace:reference`) | Pass | CORE §11.1 | M |
| RS-PR-007 | `amount` is string of atomic units (integer, no decimals/float) | Pass | CORE §5.1.2 | M |
| RS-PR-008 | EVM: `asset` is a valid checksummed contract address | Pass | CORE §5.1.2, EVM | m |
| RS-PR-009 | `exact`+`eip3009`: `extra.name` and `extra.version` present (EIP-712 domain) | Pass | EVM §1 extra fields | M |
| RS-PR-010 | `serviceName` ≤32 chars printable ASCII; `tags` ≤5×32; `iconUrl` ≤2048, http(s) | Constraint check | CORE §5.1.2 ResourceInfo | m |
| RS-PR-011 | `extensions` (if present): each entry has `info` + `schema`; `info` validates against `schema` | Pass | CORE §5.1.2 Extensions | m |
| RS-PR-012 | Consistency across repeated requests (same requirements, or deliberate dynamic pricing) | Stable or documented | CORE §5.1 | m |
| RS-PR-013 | payTo/asset match the network's CAIP-2 namespace | No `eip155`/`solana` cross-wiring (e.g. Solana address advertised on an eip155 network) | CORE §11.1 + N1/N2 | M |
| RS-PR-014 | amount is strictly positive | `amount` > 0 (not "0", not negative) — a zero/negative price is a logic hole | CORE §5.1.2 + N5 | M |

## 3. RS-PAY — Payment flow, positive path (testnet/mock only)

| ID | Test | Expected | Spec ref | Sev |
|----|------|----------|----------|-----|
| RS-PAY-001 | Valid `PAYMENT-SIGNATURE` (well-formed, funded testnet payer) | 200 + resource delivered | CORE §2, HTTP | M |
| RS-PAY-002 | Success response carries `PAYMENT-RESPONSE` header | Present, base64, schema-valid `SettlementResponse` | HTTP §Settlement Response Delivery | M |
| RS-PAY-003 | `SettlementResponse.success == true`, `transaction` non-empty, `network` matches accepted | Pass | CORE §5.3.2 | M |
| RS-PAY-004 | Settlement actually on-chain (verify tx hash on testnet explorer/RPC) | Tx exists & matches amount/payTo | CORE §6.1.3 | C |

## 4. RS-NEG — Negative tests: invalid payments MUST be rejected

These are the money tests: a server that delivers the resource despite an invalid payment loses revenue; one that settles a manipulated payload risks worse.

| ID | Test | Expected | Spec ref | Sev |
|----|------|----------|----------|-----|
| RS-NEG-001 | `PAYMENT-SIGNATURE` is garbage base64 | 400, no resource | HTTP §Error Handling | M |
| RS-NEG-002 | Valid base64, malformed JSON | 400, no resource | HTTP §Error Handling | M |
| RS-NEG-003 | Schema-valid payload, invalid signature bytes | 402, no resource | CORE §6.1.2 step 1 | C |
| RS-NEG-004 | Signature valid but recovers to address ≠ `authorization.from` | 402, no resource | EVM §1 Phase 2.1 | C |
| RS-NEG-005 | `authorization.value` < required `amount` | 402 (`..value_mismatch`) | CORE §6.1.2 step 3, §9 | C |
| RS-NEG-006 | `authorization.value` > required `amount` (exact scheme: must equal) | 402 | CORE §6.1.2 step 3 | M |
| RS-NEG-007 | `authorization.to` ≠ `payTo` (recipient tampering) | 402 (`..recipient_mismatch`) | CORE §9 | C |
| RS-NEG-008 | Expired authorization (`validBefore` in past) | 402 (`..valid_before`) | CORE §6.1.2 step 4, §9 | C |
| RS-NEG-009 | Not-yet-valid authorization (`validAfter` in future) | 402 (`..valid_after`) | CORE §9 | M |
| RS-NEG-010 | Unfunded payer (zero balance) | 402 (`insufficient_funds`), resource NOT delivered before settlement check | CORE §6.1.2 step 2 | C |
| RS-NEG-011 | `accepted` does not match any offered requirement (wrong scheme/network/asset) | 402 (`invalid_scheme`/`invalid_network`) | CORE §9 | M |
| RS-NEG-012 | `x402Version` ≠ 2 (e.g. 1, 99) | Rejected or correct V1 fallback (`invalid_x402_version`) | CORE §9 | M |
| RS-NEG-013 | Tampered `accepted.amount` (lower than server's offer, signature consistent with tampered value) | 402 — server must validate against ITS requirements, not client-supplied ones | CORE §6.1.2 step 5 | C |
| RS-NEG-014 | Payment with a well-formed but **wrong asset contract** (lookalike token) | 402 — server validates the contract address against its requirement, not the token symbol | CORE §6.1.2 step 4 + N10 | C |

## 5. RS-SEC — Security & robustness

| ID | Test | Expected | Spec ref | Sev |
|----|------|----------|----------|-----|
| RS-SEC-001 | **Replay:** resend identical valid payment after settlement | Second request rejected (nonce reuse) | CORE §10.1 | C |
| RS-SEC-002 | **Parallel replay (race):** N concurrent requests, same payload | Exactly one settlement | CORE §10.1 | C |
| RS-SEC-003 | **Cross-resource replay:** valid payment for resource A sent to resource B | Rejected | CORE §10.1 | C |
| RS-SEC-004 | Nonce not 32-byte / reused custom nonce | Rejected | CORE §5.2.2 | M |
| RS-SEC-005 | Oversized `PAYMENT-SIGNATURE` header (e.g. 1 MB) | Clean 4xx, no crash/timeout | robustness | m |
| RS-SEC-006 | Header smuggling: both `PAYMENT-SIGNATURE` and legacy V1 header present, contradictory | Deterministic, documented precedence | robustness | m |
| RS-SEC-007 | Unicode/control chars/JSON edge cases in payload fields | Clean rejection | robustness | m |
| RS-SEC-008 | Timing: response time for invalid sig vs. unknown payer comparable (info-leak smoke test) | No gross oracle | robustness | m |
| RS-SEC-009 | Resource served on 402-failure path? (content-leak check on every NEG case) | Body never contains protected resource | CORE §2 | C |
| RS-SEC-010 | **Cross-chain signature replay:** valid payload signed for network A replayed at an endpoint on network B (different chainId) | Rejected — EIP-712 domain binds chainId; the defense is the domain separator | CORE §10.1 + C0 (Fable) | C |
| RS-SEC-011 | Extreme/near-2²⁵⁶ amount values in requirements or payload | Tooling parses without overflow; endpoint responds cleanly (no crash) | robustness + N4/N13 | m |

## 6. FA — Facilitator conformance (secondary target)

| ID | Test | Expected | Spec ref | Sev |
|----|------|----------|----------|-----|
| FA-SUP-001 | `GET /supported` returns `kinds[]`, `extensions[]`, `signers{}` | Schema-valid | CORE §7.3 | M |
| FA-SUP-002 | Each kind: `x402Version`, `scheme`, CAIP-2 `network` | Pass | CORE §7.3.1 | M |
| FA-VER-001 | `POST /verify` with valid payload | `{isValid:true, payer}` | CORE §7.1 | M |
| FA-VER-002 | `/verify` with each RS-NEG payload class | `isValid:false` + correct `invalidReason` code | CORE §7.1, §9 | C |
| FA-VER-003 | `/verify` does NOT settle (no on-chain tx) | No state change | CORE §7.1 | C |
| FA-SET-001 | `POST /settle` with valid payload | `{success:true, transaction, network}`; tx on-chain | CORE §7.2 | M |
| FA-SET-002 | `/settle` with invalid payload | `{success:false, errorReason, transaction:""}` | CORE §7.2 | M |
| FA-SET-003 | Double-settle same payload | Second call fails (nonce protection) | CORE §10.1 | C |
| FA-ERR-001 | Error codes match the standard registry (§9 list) | Exact string match | CORE §9 | m |

## 7. DI — Discovery/Bazaar (Phase 2)

| ID | Test | Expected | Spec ref | Sev |
|----|------|----------|----------|-----|
| DI-001 | `GET /discovery/resources` returns schema-valid items + pagination | Pass | CORE §8.1 | M |
| DI-002 | Filters (`type`, `payTo`, `scheme`, `network`, `limit`, `offset`) honored | Pass | CORE §8.1 | m |
| DI-003 | Listed `accepts` consistent with live 402 response of the resource | Match (staleness check) | CORE §8.3 | m |

## 8. Out of scope (for now, revisit later)

- `upto` and `batch-settlement` schemes (specs exist — module after MVP)
- Permit2 / ERC-7710 asset transfer methods (EVM spec §2–3) — eip3009 first
- SVM/exact (`scheme_exact_svm.md`) — after EVM module is stable
- Extensions: `sign-in-with-x` (sessions), `bazaar`, gas sponsoring, `payment_identifier`, `offer-and-receipt`
- MCP and A2A transports (`transports-v2/mcp.md`, `a2a.md`)
- V1 backward-compat testing (`x402-specification-v1.md`) — only as "legacy detection" (RS-HS-005)

## 9. Test infrastructure notes

- **Mock facilitator:** upstream repo ships `e2e/mock-facilitator` — evaluate reuse for offline tests.
- **Testnet:** Base Sepolia (`eip155:84532`), test USDC via Circle faucet. Never mainnet funds in CI.
- **Reference servers as validation targets:** upstream `e2e/servers/*` (Express, FastAPI, Flask, Hono, Gin…) — our suite MUST pass green against these before testing third-party endpoints.
- **Calibration principle:** any test that fails against the reference implementation is a bug in our suite (or an upstream finding → report it, visibility!).

## 10. Open questions / decisions pending

1. Severity of settle-before-serve vs. serve-before-settle ordering — spec allows server flexibility (CORE §2); define what we flag.
2. How to test RS-PAY-004 cheaply without spamming testnet — batching? dedicated nightly run?
3. Report format: JSON schema for machine-readable results + Markdown/HTML renderer (decide before implementation).
4. Whether `upto` adoption justifies pulling it into MVP — check ecosystem usage at implementation start.
