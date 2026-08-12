# x402-conformance

Black-box conformance and robustness testing for [x402](https://github.com/x402-foundation/x402) payment endpoints.

Point it at any x402-paywalled URL and get a spec-traceable report: does the 402 handshake conform to the x402 V2 protocol? Are payment requirements well-formed? Does the endpoint reject what it must reject?

## New to x402? Start here

**x402** revives the long-dormant HTTP **402 Payment Required** status code as a real
protocol for paying for web resources with stablecoins — built for AI agents and
machine-to-machine commerce, where a client pays *per request* without accounts or
API keys.

The flow, in plain terms:

1. A client requests a protected URL.
2. The server replies **HTTP 402** with machine-readable **payment requirements** in a header — how much, which token, which chain, and where to pay.
3. The client builds and **cryptographically signs** a payment (e.g. an EIP-3009 stablecoin authorization) and retries the request with it.
4. The server — often via a **facilitator** service — **verifies** the payment and **settles** it on-chain, then returns the content.

Three roles show up in the commands below:

- **Resource server** — the paywalled endpoint you're testing (`check`).
- **Facilitator** — the service that verifies and settles payments (`facilitator`).
- **Bazaar / Discovery** — a directory that lists payable resources (`discovery`).

**What this tool does:** it plays the role of an outside client and checks whether an
endpoint *follows the rules*. Is the 402 handshake well-formed? Are the payment
requirements valid? And — most importantly — **does it reject invalid payments**
(wrong amount, wrong recipient, expired, replayed) instead of leaking the resource or
losing funds? Every check in the report carries an ID, a severity, and a spec reference.

**Why it matters:** x402 endpoints move real money and are meant to interoperate
across many independent implementations. A subtle bug — serving content without a
valid payment, or accepting a tampered authorization — is a direct revenue or security
leak. This suite catches those before they ship.

**Good to know:** the default checks and `--active` need **no funds and no
blockchain** — they use a throwaway key and verify that *invalid* payments are
rejected. Only the optional on-chain settlement checks (`--pay`) move real (testnet)
funds.

---

**Spec baseline:** x402 Protocol v2, `x402-foundation/x402` @ `d454eb9` (2026-06-08).
**Test catalog:** see [`docs/conformance-catalog.md`](docs/conformance-catalog.md) — every check carries an ID, severity, and spec reference.
**Support boundary:** [`docs/support-matrix.md`](docs/support-matrix.md) — exact supported, passive-only, planned, and out-of-scope mechanisms.
**Architecture:** [`docs/architecture.md`](docs/architecture.md) (how it works, with diagrams). Dated development logs (calibration, on-chain bring-up, report/robustness work) are archived under [`docs/history/`](docs/history/).
**Independent review:** [`docs/REVIEW-HANDOFF.md`](docs/REVIEW-HANDOFF.md) — safety-first review order, contracts, function index, tests, and known limits.

## Status

**v0.3.0** — working tool. CI (pytest + mypy on Python 3.11–3.13) in `.github/workflows/ci.yml`; full release notes in [`CHANGELOG.md`](CHANGELOG.md). Implemented check groups:

- **RS-HS** (handshake) and **RS-PR** (PaymentRequired schema) — passive, no payment.
- **RS-NEG** + **RS-SEC-010** (negative / security) — `--active`: signs deliberately-invalid payments and verifies the endpoint rejects them. Throwaway signer, no funds, no chain needed.
- **FA** (facilitator `/supported`, `/verify`) — the `facilitator` command.
- **DI** (discovery / Bazaar) — the `discovery` command.

- **RS-PAY** + **RS-SEC-001** (positive settlement + replay) — `check --pay`: signs a valid funded payment, settles it ON-CHAIN, verifies the tx, and confirms a replay is rejected. Confirmed live against Anvil.
- **FA-SET** (facilitator `/settle`) — `facilitator --settle`: valid settle, invalid settle, double-settle.

Calibrated against a verify-capable reference target (`tools/calibration_target.py`) and confirmed end-to-end on a local chain (Anvil + `onchain/MockUSDC.sol`, a faithful EIP-3009 token). **69 checks across the groups above; 590+ offline tests, mypy strict, CI green.**

**Solana / SVM — in progress.** The `exact` scheme on Solana works differently from EVM: the client submits a *partial-signed transaction* (an SPL/Token-2022 `TransferChecked` to the recipient's ATA, co-signed by the sponsor `feePayer` at settle time), and a verifier checks the *outcome*, not a signature. The foundations ship behind an opt-in **`[svm]`** extra — CAIP-2 `solana:*` handling, ATA derivation, a spec-faithful partial-signed transaction builder, and tamper primitives for the negative checks. A first runnable group ships: **FA-SVM** sends a valid partial-signed payload and six tampered ones to a facilitator's `/verify` (never `/settle`). The *settlement* path still needs a local validator and is **not shipped yet**. This is purely additive: without `[svm]`, the suite behaves exactly as before (no Solana dependency, no EVM path touched).

Since v0.2.0 (see [`CHANGELOG.md`](CHANGELOG.md)): six new passive checks on the challenge — four on `accepts` overspecification, two grading the challenge as JSON *text* (literals RFC 8259 does not define, duplicate keys) — the FA-SVM live `/verify` group, an MCP server for the passive surface, a machine-readable `inconclusiveReason` (report 1.3), and the Algorand CAIP-2 alignment that landed upstream as x402#2931.

## Install

```bash
pip install -e ".[dev]"     # includes eth-account for active checks
# optional extras: [onchain] for --pay settlement (web3), [svm] for the Solana/SVM foundations (solders)
```

## Usage

```bash
# Passive checks against a resource endpoint
x402-conformance check https://api.example.com/premium-data

# Also run active negative checks (sends invalid payments; throwaway signer)
x402-conformance check https://api.example.com/premium-data --active

# Positive settlement: both a funded testnet key and matching RPC are mandatory
x402-conformance check https://api.example.com/premium-data --pay \
  --rpc-url https://sepolia.base.org --signer-key "$X402_TESTNET_PAYER_KEY"

# Pass a unique string from the paid resource to also catch content leaked on a rejection
x402-conformance check https://api.example.com/premium-data --active --resource-marker "SECRET_TOKEN"

# Facilitator checks (+ /verify negatives when a resource is given)
x402-conformance facilitator https://facilitator.example --resource https://api.example.com/premium-data

# Direct facilitator settlement has the same key/RPC safety boundary
x402-conformance facilitator https://facilitator.example --settle \
  --resource https://api.example.com/premium-data \
  --rpc-url https://sepolia.base.org --signer-key "$X402_TESTNET_PAYER_KEY"

# Discovery / Bazaar checks
x402-conformance discovery https://facilitator.example

# Developer fix-it report: failures only, grouped by severity, each with what's
# wrong + how to fix + the spec reference (instead of the full pass/fail table)
x402-conformance check https://api.example.com/premium-data --active --fix

# Machine-readable output + CI-friendly exit code (1 on major/critical failure)
x402-conformance check https://api.example.com/premium-data --json report.json --markdown report.md

# SARIF 2.1.0 findings — upload to a GitHub code-scanning / Security tab or a bug-bounty platform
x402-conformance check https://api.example.com/premium-data --sarif results.sarif

# Explain a check in plain language (offline): what it tests, severity, spec ref, how to fix.
# A prefix lists matches; no argument lists the whole catalog.
x402-conformance explain RS-NEG-007
x402-conformance explain FA-VER

# Diff two JSON reports — "did my fix work?" (fixed / regressed / still-failing / added / removed).
# Exit 1 if a previously-passing check regressed, so it doubles as a CI regression gate.
x402-conformance diff before.json after.json

# Read-only batch scan: /supported only.
x402-conformance scan targets.txt --json scan.json

# Active/no-settlement scan: signed invalid /verify probes require explicit authorization.
x402-conformance scan targets.txt --resource https://api.example.com/premium-data \
  --authorize-active-verify --json scan.json
```

Exit codes: `0` assessed and conformant, `1` not conformant (a major/critical check failed),
`2` inconclusive, unreachable, or invalid input.
`explain` always exits `0`; `diff` exits `1` on a regression; `scan` exits `1` if any reachable target is non-conformant.

The `check` command never changes the selected HTTP method implicitly. Use `--method POST`
when the protected resource requires POST.

### Payment safety boundary

- Payment signing is allowed only for `eip155:1337`, `eip155:31337`,
  `eip155:84532` (Base Sepolia), and `eip155:11155111` (Sepolia). A future SVM
  runner may use Solana devnet/testnet; Solana mainnet is denied.
- Mainnets and unknown networks are rejected before a payload is built. The CLI
  repeats the preflight before signer creation, and the runner rechecks the actual
  challenge in case it changes between requests. There is no mainnet override.
- `--pay` and `facilitator --settle` require `--rpc-url`; `eth_chainId` must match
  the advertised CAIP-2 network. They also require a supplied funded testnet key
  (`--signer-key` or `X402_TESTNET_PAYER_KEY`) rather than a random signer.
- Payment, `/verify`, `/settle`, and RPC requests never follow redirects. This
  prevents `PAYMENT-SIGNATURE` headers or settlement bodies crossing an origin or
  an HTTPS-to-HTTP downgrade.
- Auto-discovered TOML config cannot enable `active`, `pay`, or `timing`; those
  modes require an explicit flag on each run. Config keys are type/range checked.

## MCP server (for coding agents)

`x402-conformance-mcp` exposes the **passive** surface over the Model Context
Protocol, so an agent in Claude Code, Claude Desktop or Cursor can check an
endpoint without leaving the editor.

```bash
pip install "x402-conformance[mcp]"
```

```jsonc
// Claude Code: .mcp.json — or the equivalent block in your client's config
{
  "mcpServers": {
    "x402-conformance": { "command": "x402-conformance-mcp" }
  }
}
```

Four tools: `check_endpoint` (two unpaid requests, verdict plus every failure
with its detail and spec reference), `explain_check` (offline — what a check ID
means and how to fix it), `diff_reports` (did my fix work, did anything
regress), and `check_discovery` (DI-* against a Bazaar base URL). `check_endpoint`
returns the full versioned report alongside the digest, so it can be handed
straight back to `diff_reports` without writing a file.

**It cannot sign or settle a payment, and it cannot probe a facilitator's
`/verify`.** Not by default — at all. The tools take no signer key, no RPC URL
and no `active` flag, and the module never imports the signing path
(`tests/test_mcp_server.py` enforces both). The payment-safety invariant says
transactional modes need an explicit flag per run so they cannot be switched on
by configuration nobody read; an agent choosing for itself is that same case.
Those modes stay in the CLI, where a person types the flag.

Transport defaults to stdio, which is what an editor spawns. Set
`X402_MCP_TRANSPORT=sse` or `streamable-http` for a shared deployment.

## Development

```bash
pytest          # the suite's own tests (offline, mocked transport) — 590+ tests
mypy            # strict type checking
python tools/check_function_docs.py  # every production/tool function has a docstring

# Calibrate the checks against a verify-capable reference server:
python tools/calibration_target.py 4500 &
x402-conformance check http://127.0.0.1:4500/data --active
x402-conformance facilitator http://127.0.0.1:4500 --resource http://127.0.0.1:4500/data

# One-shot live verification of the report-schema / EIP-55 / leak / extreme-amount
# features (spins the target up in each bug mode and asserts each check catches it):
python tools/verify_new_features.py
```

Live-verification runbook (dated, archived): [`docs/history/verify-new-features.md`](docs/history/verify-new-features.md).

The reproducible dependency workflow and complete local release gate are in
[`docs/supply-chain.md`](docs/supply-chain.md).

No mainnet funds are ever used. Payment-flow tests run against Base Sepolia or mocks only.

## Contributing

Gates, the checklist for adding a check, and the boundary of what this project accepts
are in [`CONTRIBUTING.md`](CONTRIBUTING.md). Vulnerabilities go to
[`SECURITY.md`](SECURITY.md), not to a public issue.

## License

Apache-2.0
