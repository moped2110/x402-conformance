# Known Issues — x402-conformance

As of: 2026-06-29. Known limitations, blockers, and pending decisions. Resolved
items are trimmed once they're finalized; the full backlog lives in `../TODO.md`.

---

### I-4 · Testnet strategy: on-chain settlement
The signature level (recovery, domain binding) is testable without a chain and is
done. Real settlement (balance, simulation, RS-PAY-004) is **confirmed live against
a local Anvil chain** (see `history/onchain-2026-06-11.md`); what's still open is
the strategy for a *public* testnet run — nightly vs. on-demand against Base Sepolia
with a funded faucet payer. Hard line: never mainnet money. → Backlog T-09.

### I-5 · Silence on an unreachable facilitator (calibration insight, not a suite bug)
For the unpaid 402 response, the reference server initializes its facilitator via
`GET /supported`. If the facilitator is unreachable, the endpoint returns **HTTP 500
on all routes** instead of 402. Possible future check: "does the endpoint respond
cleanly even during facilitator problems?"

## Environment notes (for reproducibility)
- The x402 SDK facilitator client inherits proxy environment variables. Behind a
  proxy, without `socksio` installed and without clearing the proxy vars
  (`env -u ALL_PROXY …`), every request fails with a `ProxyError 403`.

## Recently resolved
- **I-3 License** — `LICENSE` (Apache-2.0) added, matches `pyproject` and upstream.
- **I-6 Upstream findings** — the three calibration findings were filed upstream:
  the silent-500 settlement path as [#2603](https://github.com/x402-foundation/x402/issues/2603)
  and the invalid Bazaar e2e extension as [#2604](https://github.com/x402-foundation/x402/issues/2604)
  (the third, undocumented facilitator fields, was already fixed upstream). Detail
  in `history/calibration-2026-06-09.md`.
