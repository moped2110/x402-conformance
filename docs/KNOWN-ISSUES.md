# Known Issues — x402-conformance

As of: 2026-06-09. Known limitations, blockers, and pending decisions. Completed items are moved out once they are finalized in the backlog (`../TODO.md`).

---

### I-3 · License
`pyproject.toml` declares Apache-2.0; `LICENSE` file added (T-02). Chosen for consistency with upstream x402.

### I-4 · Testnet strategy: on-chain settlement
The signature level (recovery, domain binding) is testable without a chain and is done. For real settlement (balance, simulation, RS-PAY-004), we need a Base Sepolia RPC + funded testnet payer (Circle faucet USDC) or a local Anvil fork. Concrete strategy (nightly run vs. on-demand) still to be determined. Hard line: never mainnet money.

## Insights from calibration (not bugs in our suite)

### I-5 · Silence on unreachable facilitator
Even for the unpaid 402 response, the reference server initializes its facilitator via `GET /supported`. If the facilitator is unreachable, the endpoint returns **HTTP 500 on all routes** instead of 402.
- **For the suite:** Possibly add a dedicated check later: "does the endpoint respond cleanly even during facilitator problems?".

### I-6 · Upstream findings not yet reported
Three findings (missing fields, silent 500, invalid Bazaar extensions) are documented in `docs/calibration-2026-06-09.md` but not yet filed as issues. → Backlog T-05.

## Environment notes (for reproducibility)
- The x402 SDK facilitator client inherits proxy environment variables. Behind a proxy, without `socksio` installed and without clearing the proxy vars (`env -u ALL_PROXY …`), every request fails with a `ProxyError 403`.
