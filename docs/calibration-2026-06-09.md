# Calibration Run — 2026-06-09

**Goal:** Per the calibration principle (CLAUDE.md), the suite must run green against the upstream reference implementation before it is allowed to judge third-party endpoints. Any failure against the reference is a suite bug — or an upstream finding.

**Setup:**
- Target: upstream e2e FastAPI reference server (`e2e/servers/fastapi`, x402 Python SDK, editable from repo @ `d454eb9`)
- Facilitator: local mock serving only `GET /supported` (see `tools/mock_facilitator.py`)
- Suite version: 0.0.1 (18 checks: RS-HS-001…006, RS-PR-001…012)

## Result: 7/7 endpoints CONFORMANT, zero false positives

| Endpoint | Scheme / transfer method | Verdict |
|----------|--------------------------|---------|
| /exact/evm/eip3009 | exact / eip3009 | ✅ 18 pass |
| /exact/evm/permit2-eip2612GasSponsoring | exact / permit2 | ✅ 17 pass, 1 correct skip (RS-PR-009) |
| /exact/evm/permit2-erc20ApprovalGasSponsoring | exact / permit2 | ✅ |
| /upto/evm/permit2 | upto / permit2 | ✅ |
| /upto/evm/permit2-eip2612GasSponsoring | upto / permit2 | ✅ |
| /batch-settlement/evm/eip3009 | batch-settlement / eip3009 | ✅ |
| /batch-settlement/evm/permit2 | batch-settlement / permit2 | ✅ |

RS-PR-009 (EIP-712 domain fields) skips correctly on permit2-only endpoints — the check's eip3009 gating works as designed. The suite needed **no fixes**: zero checks misfired against the reference implementation.

## Upstream findings (potential issues to report — visibility opportunity)

1. **Spec gap — undocumented facilitator capability fields.** The reference SDK *requires* per-kind `extra` fields in the `/supported` response that the core spec §7.3 does not mention: `upto` needs `extra.facilitatorAddress` (hard `ValueError` otherwise), `batch-settlement` needs `extra.receiverAuthorizer`. A facilitator built strictly to spec breaks SDK-based servers using those schemes. → candidate for an upstream spec/docs issue.
2. **Silent 500 on requirements-building errors.** The SDK middleware catches `Exception` without logging and returns `{"error": "Failed to process request"}` with HTTP 500. Operators get zero diagnostics. Status mapping is spec-conformant (Server Error → 500), but the missing log is a DX problem. → candidate for an SDK issue/PR.
3. **Reference server emits invalid bazaar extensions.** Every protected route in `e2e/servers/fastapi/main.py` logs `invalid bazaar extension: 'method' is a required property` at startup — the e2e server's own discovery declarations fail SDK validation. → candidate for an e2e fix PR.

## Environment notes (sandbox-specific, not findings)

- SDK's facilitator client inherits proxy env vars; without `socksio` installed it 500s on every request (sandbox proxy setup). Irrelevant outside the sandbox, but it shows: facilitator unreachability ⇒ total endpoint outage. A monitoring angle worth remembering for the SaaS layer.
- Initial 500s on ALL endpoints had one root cause: `initialize()` requires a reachable facilitator `/supported` at first request. Resource servers hard-depend on their facilitator even for unpaid 402 responses — another monitoring-relevant fact.

## Follow-ups

- [ ] File upstream issues for findings 1–3 (after re-checking against latest main) — good first visibility in the x402 community.
- [ ] Calibrate against further reference servers (flask, express/hono via node) before v0.1 release.
- [ ] Add `upto`/`batch-settlement` awareness to RS-PR checks (currently scheme-agnostic except RS-PR-009) once those schemes enter MVP scope.
