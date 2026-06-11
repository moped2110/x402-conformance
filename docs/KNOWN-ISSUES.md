# Known Issues — x402-conformance

As of: 2026-06-09. Known limitations, blockers, and pending decisions. Completed items are moved out once they are finalized in the backlog (`../TODO.md`) or decision log (`../../ROADMAP.md`).

---

### I-1 · Git unusable in the sandbox
`git init` fails in the Cowork sandbox: the mounted project directory does not tolerate Git's atomic file operations (`config.lock` cannot be removed, `Operation not permitted`). The `.git` directory had to be manually removed.
- **Impact:** I cannot create a real Git repository within the sandbox. Commits must be made from the host machine (Mario's environment).
- **Mitigation:** Continue development without local Git state in the sandbox; rely on the host for version control.

### I-13 · Mount sync delays (Cowork sandbox)
In the Cowork sandbox, **newly created files synchronize immediately** to the bash mount, but **in-place edits to existing files are delayed/unreliable**. This led to pytest running against outdated code (checks appeared missing even though they were in the source) and, in case of conflicting writes, even a file being corrupted.
- **Impact:** Only within the sandbox; Mario's local environment is unaffected.
- **Workaround (applied):** Completely rewrite/converge code that needs to be executed via bash after edits; run tests with a fresh `PYTHONPYCACHEPREFIX`. Documentation files are non-critical (they are not executed).

### I-8 · Foundry/Anvil not installable in the sandbox
The Foundry installer (`https://foundry.paradigm.xyz`) is blocked by the sandbox proxy with a **403**; `anvil` is not present. This means no local EVM chain is available in this environment for real on-chain settlement (RS-PAY).
- **Open:** Real settlement (RS-PAY-004) + balance-dependent rejection require Anvil/Base Sepolia on Mario's machine. Only affects the sandbox.

### I-2 · Python 3.10 in the sandbox, project requires 3.11+
The sandbox only has Python 3.10. `pyproject.toml` requires `>=3.11`. Tests and mypy still run green in the sandbox because the code doesn't use 3.11-only features yet.
- **Decision:** Keep 3.11+ requirement to use modern type hinting and performance improvements; Mario has 3.11+ locally.

### I-3 · License not yet final
`pyproject.toml` declares Apache-2.0, but there is no LICENSE file. → Backlog T-02. Recommendation: Apache-2.0 (consistency with upstream x402).

### I-4 · Testnet Strategy: On-Chain decided, prepare settlement tests
**Decision (Mario, 2026-06-10):** We want to test on-chain and are now preparing for it. License remains Apache-2.0.
The signature level (recovery, domain binding) is already testable without a chain and is done. For real settlement (balance, simulation, RS-PAY-004), we still need: Base Sepolia RPC + funded testnet payer (Circle Faucet USDC) or a local Anvil fork. Concrete strategy (nightly run vs. on-demand) still to be determined. Hard line: never mainnet money.

## Insights from calibration (not bugs in our suite)

### I-5 · Silence on unreachable Facilitator
Even for the unpaid 402 response, the reference server initializes its facilitator via `GET /supported`. If the facilitator is unreachable, the endpoint returns **HTTP 500 on all routes** instead of 402.
- **Relevance:** Selling point for the later monitoring SaaS (T-13) — facilitator failure = total failure, which you want to monitor.
- **For the suite:** Possibly add a dedicated check later: "does the endpoint respond cleanly even during facilitator problems?".

### I-6 · Upstream findings not yet reported
Three findings (missing fields, silent 500, invalid Bazaar extensions) are documented in `docs/calibration-2026-06-09.md` but not yet filed as issues. → Backlog T-05.

## Tooling Notes (sandbox-specific, for reproducibility)
- The x402 SDK Facilitator client inherits proxy environment variables. Without `socksio` and without removing proxy vars (`env -u ALL_PROXY …`), every request fails with `ProxyError 403`. Not an issue locally outside the sandbox.
