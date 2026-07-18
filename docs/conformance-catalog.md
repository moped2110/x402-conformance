# x402 Conformance Test Catalog

**Spec baseline:** x402 Protocol v2 — repo `x402-foundation/x402`, commit `d454eb9` (2026-06-08)
**Documents referenced:**
- CORE = `specs/x402-specification-v2.md`
- HTTP = `specs/transports-v2/http.md`
- EVM = `specs/schemes/exact/scheme_exact_evm.md`

**Status:** this catalog is the full *planned* set with spec traceability; some IDs are aspirational. See "Implementation status" below for what actually ships. Severity: **C**ritical (security/funds at risk), **M**ajor (spec violation, interop broken), **m**inor (robustness/quality).

## Implementation status (v0.2.0)

**Implemented & tested (63 checks):**
- RS-HS-001…007, RS-PR-001…016 — passive (`check`). RS-PR-008 now does full EIP-55 checksum validation (mixed-case addresses) when keccak is available. RS-PR-015 is an opt-in structural check for the community `jp402.tax` breakdown on a live 402 (SKIP unless advertised); RS-PR-016 validates the qualified-invoice metadata on the OpenAPI surface (`/openapi.json`, fetched only when `jp402` is advertised).
- RS-NEG-001/002/003/004/005/006/007/008/009/011/012/013/014/015 + RS-SEC-003 + RS-SEC-004 + RS-SEC-005 + RS-SEC-006 + RS-SEC-007 + RS-SEC-010 + RS-SEC-011 — active (`check --active`)
- RS-PAY-001…004 + RS-SEC-001 (replay) + RS-SEC-002 (race) — on-chain (`check --pay`)
- FA-SUP-001/002, FA-VER-002/003/004, FA-ERR-001 — `facilitator`; FA-SET-001/002/003 — `facilitator --settle`
- DI-001/002/003 — `discovery`

RS-SEC-009 (content-leak on the rejection path) is enforced inside every active check; `check --active --resource-marker <s>` additionally flags a rejected body that still contains the protected content.

RS-SEC-008 (timing oracle) is an opt-in, MINOR/advisory probe (`check --timing`): it flags a
gross, reproducible timing gap between two rejection reasons (wrong-signature vs. wrong-amount) and
never gates the verdict. Timing is noisy, so a positive is a strong signal but its absence is not
proof.

**Planned (in this catalog, not yet shipped):** RS-NEG-010, FA-VER-001, FA-VER-005. RS-SEC-003 now ships as a MINOR *advisory* cross-resource-binding probe (single-request resource relabel; overlaps the RS-NEG-013 "validate `accepted` against your own offer" principle applied to `resource`) — it never gates the verdict. The full economic exploit (replay of a *settled* payment across resources) needs two resources + settlement and is out of the single-endpoint black-box scope.

**Target types:**
- **RS** = Resource Server (the x402-paywalled endpoint) — primary MVP target
- **FA** = Facilitator (`/verify`, `/settle`, `/supported`) — secondary target
- **DI** = Discovery/Bazaar endpoint — Phase 2

---

## 1. RS-HS — 402 Handshake (unpaid request)

| ID | Test | Expected | Spec ref | Sev | Status |
|----|------|----------|----------|-----|--------|
| RS-HS-001 | GET/POST without payment headers | Status 402 | HTTP §Payment Required Signaling | M | implemented |
| RS-HS-002 | 402 response carries `PAYMENT-REQUIRED` header | Header present | HTTP §Payment Required Signaling | M | implemented |
| RS-HS-003 | `PAYMENT-REQUIRED` header is valid base64 | Decodes cleanly | HTTP §Payment Required Signaling | M | implemented |
| RS-HS-004 | Decoded header is valid JSON matching `PaymentRequired` schema | Schema-valid | CORE §5.1 | M | implemented |
| RS-HS-005 | Legacy `X-*` headers absent in V2 responses (deprecated) | No `X-PAYMENT` etc.; flag if V1-only | HTTP §Header Summary | m | implemented |
| RS-HS-006 | Response body usable alongside 402 (no protocol data required in body) | Protocol info complete via headers alone | HTTP §Response Body | m | implemented |
| RS-HS-007 | 402 with payment details is not cacheable | `Cache-Control` is `no-store`/`private` (no `public`, no long `max-age`); else CDN/proxy could serve a stale paywall | RFC 9111 + PR1 (testcase-integration-analysis) | M | implemented |

## 2. RS-PR — PaymentRequired schema content

| ID | Test | Expected | Spec ref | Sev | Status |
|----|------|----------|----------|-----|--------|
| RS-PR-001 | `x402Version` present and `== 2` | Pass; a recognised **x402 v1** endpoint is a SKIP ("speaks v1, not v2") and the v2-shape checks (RS-PR-002/005, RS-HS-004) skip too, so a working v1 endpoint isn't flagged as broken — only an *unknown* version fails | CORE §5.1.2 | M | implemented |
| RS-PR-002 | `resource` object present with required `url` | Pass | CORE §5.1.2 | M | implemented |
| RS-PR-003 | `resource.url` matches the requested resource (no mismatch/spoofing) | Match | CORE §5.1.2 | M | implemented |
| RS-PR-004 | `accepts` array present, ≥1 entry | Pass | CORE §5.1.2 | M | implemented |
| RS-PR-005 | Each accepts entry: required fields `scheme`, `network`, `amount`, `asset`, `payTo`, `maxTimeoutSeconds` | All present | CORE §5.1.2 | M | implemented |
| RS-PR-006 | `network` is valid CAIP-2 (`namespace:reference`) | Pass | CORE §11.1 | M | implemented |
| RS-PR-007 | `amount` is string of atomic units (integer, no decimals/float) | Pass | CORE §5.1.2 | M | implemented |
| RS-PR-008 | EVM: `asset` is a valid checksummed contract address | Pass | CORE §5.1.2, EVM | m | implemented |
| RS-PR-009 | `exact`+`eip3009`: `extra.name` and `extra.version` present (EIP-712 domain) | Pass | EVM §1 extra fields | M | implemented |
| RS-PR-010 | `serviceName` ≤32 chars printable ASCII; `tags` ≤5×32; `iconUrl` ≤2048, http(s) | Constraint check | CORE §5.1.2 ResourceInfo | m | implemented |
| RS-PR-011 | `extensions` (if present): each entry structurally carries `info` + `schema` | Structural pass; JSON-Schema evaluation is not performed by this check | CORE §5.1.2 Extensions | m | implemented |
| RS-PR-012 | Consistency across repeated requests (same requirements, or deliberate dynamic pricing) | Stable or documented | CORE §5.1 | m | implemented |
| RS-PR-013 | payTo/asset match the network's CAIP-2 namespace | No `eip155`/`solana` cross-wiring (e.g. Solana address advertised on an eip155 network) | CORE §11.1 + N1/N2 | M | implemented |
| RS-PR-014 | amount is strictly positive | `amount` > 0 (not "0", not negative) — a zero/negative price is a logic hole | CORE §5.1.2 + N5 | M | implemented |
| RS-PR-016 | **jp402 OpenAPI invoice** (when `jp402` is advertised) is structurally valid | The qualified-invoice metadata (`registrationNumber` `^T[0-9]{13}$`) lives in the seller's OpenAPI doc (`x-jp402.invoice` at `info` / per-operation), not on the live 402. The runner fetches `/openapi.json` only when the 402 advertises `jp402`; an unreachable/absent doc is a SKIP, a present-but-malformed invoice FAILs. Community extension, MINOR | jp402-registry | m | implemented |
| RS-PR-015 | **jp402 tax** breakdown (if present) is structurally consistent | Opt-in JP-rail check: SKIP unless `jp402` advertised on the live 402; validates the `tax` block (`excl_jpyc`/`vat_jpyc`/`rate`) — `vat == excl * rate` and `excl + vat` scaling onto `amount` by a power of ten. The qualified-invoice `registrationNumber` (`^T[0-9]{13}$`) lives in the OpenAPI doc (`x-jp402.invoice`), validated by `find_invoice_blocks` + `validate_invoice`. Community extension (jp402-registry), not core; MINOR so it never gates | jp402-registry | m | implemented |

## 3. RS-PAY — Payment flow, positive path (testnet/mock only)

| ID | Test | Expected | Spec ref | Sev | Status |
|----|------|----------|----------|-----|--------|
| RS-PAY-001 | Valid `PAYMENT-SIGNATURE` (well-formed, funded testnet payer) | 200 + resource delivered | CORE §2, HTTP | M | implemented |
| RS-PAY-002 | Success response carries `PAYMENT-RESPONSE` header | Present, base64, schema-valid `SettlementResponse` | HTTP §Settlement Response Delivery | M | implemented |
| RS-PAY-003 | `SettlementResponse.success == true`, `transaction` non-empty, `network` matches accepted | Pass | CORE §5.3.2 | M | implemented |
| RS-PAY-004 | Settlement actually on-chain (verify tx hash on testnet explorer/RPC) | Tx exists & matches amount/payTo | CORE §6.1.3 | C | implemented |

## 4. RS-NEG — Negative tests: invalid payments MUST be rejected

These are the money tests: a server that delivers the resource despite an invalid payment loses revenue; one that settles a manipulated payload risks worse.

| ID | Test | Expected | Spec ref | Sev | Status |
|----|------|----------|----------|-----|--------|
| RS-NEG-001 | `PAYMENT-SIGNATURE` is garbage base64 | 400, no resource | HTTP §Error Handling | M | implemented |
| RS-NEG-002 | Valid base64, malformed JSON | 400, no resource | HTTP §Error Handling | M | implemented |
| RS-NEG-003 | Schema-valid payload, invalid signature bytes | 402, no resource | CORE §6.1.2 step 1 | C | implemented |
| RS-NEG-004 | Signature valid but recovers to address ≠ `authorization.from` | 402, no resource | EVM §1 Phase 2.1 | C | implemented |
| RS-NEG-005 | `authorization.value` < required `amount` | 402 (`..value_mismatch`) | CORE §6.1.2 step 3, §9 | C | implemented |
| RS-NEG-006 | `authorization.value` > required `amount` (exact scheme: must equal) | 402 | CORE §6.1.2 step 3 | M | implemented |
| RS-NEG-007 | `authorization.to` ≠ `payTo` (recipient tampering) | 402 (`..recipient_mismatch`) | CORE §9 | C | implemented |
| RS-NEG-008 | Expired authorization (`validBefore` in past) | 402 (`..valid_before`) | CORE §6.1.2 step 4, §9 | C | implemented |
| RS-NEG-009 | Not-yet-valid authorization (`validAfter` in future) | 402 (`..valid_after`) | CORE §9 | M | implemented |
| RS-NEG-010 | Unfunded payer (zero balance) | 402 (`insufficient_funds`), resource NOT delivered before settlement check | CORE §6.1.2 step 2 | C | planned |
| RS-NEG-011 | `accepted` does not match any offered requirement (wrong scheme/network/asset) | 402 (`invalid_scheme`/`invalid_network`) | CORE §9 | M | implemented |
| RS-NEG-012 | `x402Version` ≠ 2 (e.g. 1, 99) | Rejected or correct V1 fallback (`invalid_x402_version`) | CORE §9 | M | implemented |
| RS-NEG-013 | Tampered `accepted.amount` (lower than server's offer, signature consistent with tampered value) | 402 — server must validate against ITS requirements, not client-supplied ones | CORE §6.1.2 step 5 | C | implemented |
| RS-NEG-014 | Payment with a well-formed but **wrong asset contract** (lookalike token) | 402 — server validates the contract address against its requirement, not the token symbol | CORE §6.1.2 step 4 + N10 | C | implemented |
| RS-NEG-015 | Payment whose **asset is an EOA** (no contract code) | 402 — calling transferWithAuthorization on an EOA never reverts, so settlement is a silent no-op; server must reject (`asset_not_deployed_contract`) before settling | CORE §6.1.2 step 4 + x402#2554 | C | implemented |

## 5. RS-SEC — Security & robustness

| ID | Test | Expected | Spec ref | Sev | Status |
|----|------|----------|----------|-----|--------|
| RS-SEC-001 | **Replay:** resend identical valid payment after settlement | Second request rejected (nonce reuse) | CORE §10.1 | C | implemented |
| RS-SEC-002 | **Parallel replay (race):** N concurrent requests, same payload | Exactly one settlement (positive-evidence only — a PASS means no race was observed this run, not that none exists; a fast server can serialize and pass by luck. A FAIL is a hard finding.) | CORE §10.1 | C | implemented |
| RS-SEC-003 | **Cross-resource binding:** an otherwise-valid payment whose claimed `resource` differs from the requested one | Rejected — server binds payment↔resource (advisory; the resource label is unsigned, so MINOR/never-gates) | CORE §10.1 + arXiv:2605.11781 | m | implemented |
| RS-SEC-004 | Nonce not 32-byte / reused custom nonce | Rejected | CORE §5.2.2 | M | implemented |
| RS-SEC-005 | Oversized `PAYMENT-SIGNATURE` header (e.g. 1 MB) | Clean 4xx, no crash/timeout | robustness | m | implemented |
| RS-SEC-006 | Header smuggling: an invalid v2 payment sent with a contradictory legacy V1 `X-PAYMENT` header | Still rejected — the legacy header must not smuggle an invalid payment past v2 validation; no 5xx on duplicate headers (arXiv:2605.11781 III) | robustness | m | implemented |
| RS-SEC-007 | Unicode/control chars/JSON edge cases in payload fields | Clean rejection | robustness | m | implemented |
| RS-SEC-008 | Timing: response time for invalid sig vs. unknown payer comparable (info-leak smoke test) | No gross oracle | robustness | m | implemented |
| RS-SEC-010 | **Cross-chain signature replay:** valid payload signed for network A replayed at an endpoint on network B (different chainId) | Rejected — EIP-712 domain binds chainId; the defense is the domain separator | CORE §10.1 + C0 | C | implemented |
| RS-SEC-011 | Extreme/near-2²⁵⁶ amount values in requirements or payload | Tooling parses without overflow; endpoint responds cleanly (no crash) | robustness + N4/N13 | m | implemented |

## 6. FA — Facilitator conformance (secondary target)

| ID | Test | Expected | Spec ref | Sev | Status |
|----|------|----------|----------|-----|--------|
| FA-SUP-001 | `GET /supported` **if present** returns `kinds[]`, `extensions[]`, `signers{}` | Schema-valid when present; absent (404) is SKIP — `/supported` is optional (§7.3), requirements come inline in the 402 | CORE §7.3 | M | implemented |
| FA-SUP-002 | Each kind is well-formed: `x402Version` 1 or 2, `scheme`, non-empty `network`; a **v2** kind's network is CAIP-2 (a **v1** kind carries a legacy name, e.g. `base-sepolia`) | Pass — version-aware, so a facilitator serving both v1+v2 isn't false-flagged | CORE §7.3.1 | M | implemented |
| FA-VER-001 | `POST /verify` with valid payload | `{isValid:true, payer}` | CORE §7.1 | M | planned |
| FA-VER-002 | `/verify` with each RS-NEG payload class | `isValid:false` + correct `invalidReason` code | CORE §7.1, §9 | C | implemented |
| FA-VER-003 | `/verify` with an **asset that is an EOA** (no bytecode) | `isValid:false` — facilitator must pre-flight `eth_getCode` and reject (`asset_not_deployed_contract`), else settlement is a silent no-op | CORE §7.1 + x402#2554 | C | implemented |
| FA-VER-005 | `/verify` does NOT settle (no on-chain tx) | No state change | CORE §7.1 | C | planned |
| FA-VER-004 | `/verify` handles invalid client input (EOA asset) with a clean 4xx/200, not a 5xx | No server error on malformed input — a `balanceOf`/parse exception must surface as `isValid:false`, not HTTP 500 | CORE §7.1 (robustness) | m | implemented |
| FA-SET-001 | `POST /settle` with valid payload | `{success:true, transaction, network}`; tx on-chain | CORE §7.2 | M | implemented |
| FA-SET-002 | `/settle` with invalid payload | `{success:false, errorReason, transaction:""}` | CORE §7.2 | M | implemented |
| FA-SET-003 | Double-settle same payload | Second call fails (nonce protection) | CORE §10.1 | C | implemented |
| FA-ERR-001 | Error codes match the standard registry (§9 list) | Exact string match | CORE §9 | m | implemented |

## 7. DI — Discovery/Bazaar (Phase 2)

| ID | Test | Expected | Spec ref | Sev | Status |
|----|------|----------|----------|-----|--------|
| DI-001 | `GET /discovery/resources` strictly validates top-level `x402Version`, each item's `resource`, `type`, `x402Version`, `accepts`, `lastUpdated`, optional `extensions`, every core `PaymentRequirements` field, and `pagination.{limit,offset,total}` including bounds | Pass | CORE §8.1, §8.3 | M | implemented |
| DI-002 | Filters (`type`, `payTo`, `scheme`, `network`, `extensions`, `limit`, `offset`) and offset-pagination semantics honored | Pass | CORE §8.1 | m | implemented |
| DI-003 | Listed `accepts` consistent with the resource's live 402; cross-fetches are capped, DNS-pinned, redirect-revalidated, public-address-only by default, and private destinations require an explicit exact-host/IP/CIDR allowlist | Match (staleness check); unsafe/unreachable resources are not fetched and remain inconclusive | CORE §8.3 | m | implemented |

## 8. Coverage boundary

The versioned [`support-matrix.md`](support-matrix.md) is authoritative. In
summary, Permit2, ERC-7710, runnable SVM, `upto`, and `batch-settlement` are
planned. V1 and unsupported network families receive shared-envelope checks
only. MCP/A2A transports, mainnet payment execution, custody, and legal/tax
certification are out of scope.

## 9. Test infrastructure notes

- **Mock facilitator:** offline transports and the local calibration facilitator
  cover strict verify/settle behavior without third-party traffic.
- **Testnet:** Base Sepolia (`eip155:84532`), test USDC via Circle faucet. Never mainnet funds in CI.
- **Reference servers as validation targets:** upstream `e2e/servers/*` (Express, FastAPI, Flask, Hono, Gin…) — our suite MUST pass green against these before testing third-party endpoints.
- **Calibration principle:** any test that fails against the reference implementation is a bug in our suite (or an upstream finding → report it, visibility!).

## 10. Deferred decisions

Public-testnet cadence, additional reference-server calibration, and adoption
thresholds for planned mechanisms are recorded in the support matrix. The
machine-readable report contract is version `1.1` and validated by
`report.schema.json`.
