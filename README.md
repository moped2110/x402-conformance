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
**Architecture:** [`docs/architecture.md`](docs/architecture.md) (how it works, with diagrams) · [`docs/reporting-and-robustness-2026-06-12.md`](docs/reporting-and-robustness-2026-06-12.md) (report schema, EIP-55, content-leak marker, extreme-amount).

## Status

**v0.1.0** — working tool. CI (pytest + mypy on Python 3.11–3.13) in `.github/workflows/ci.yml`; full release notes in [`CHANGELOG.md`](CHANGELOG.md). Implemented check groups:

- **RS-HS** (handshake) and **RS-PR** (PaymentRequired schema) — passive, no payment.
- **RS-NEG** + **RS-SEC-010** (negative / security) — `--active`: signs deliberately-invalid payments and verifies the endpoint rejects them. Throwaway signer, no funds, no chain needed.
- **FA** (facilitator `/supported`, `/verify`) — the `facilitator` command.
- **DI** (discovery / Bazaar) — the `discovery` command.

- **RS-PAY** + **RS-SEC-001** (positive settlement + replay) — `check --pay`: signs a valid funded payment, settles it ON-CHAIN, verifies the tx, and confirms a replay is rejected. Confirmed live against Anvil.
- **FA-SET** (facilitator `/settle`) — `facilitator --settle`: valid settle, invalid settle, double-settle.

Calibrated against a verify-capable reference target (`tools/calibration_target.py`) and confirmed end-to-end on a local chain (Anvil + `onchain/MockUSDC.sol`, a faithful EIP-3009 token). See `docs/onchain-2026-06-11.md`. 39 checks across 5 groups; 102 offline tests.

## Install

```bash
pip install -e ".[dev]"     # includes eth-account for active checks
```

## Usage

```bash
# Passive checks against a resource endpoint
x402-conformance check https://api.example.com/premium-data

# Also run active negative checks (sends invalid payments; throwaway signer)
x402-conformance check https://api.example.com/premium-data --active

# Pass a unique string from the paid resource to also catch content leaked on a rejection
x402-conformance check https://api.example.com/premium-data --active --resource-marker "SECRET_TOKEN"

# Facilitator checks (+ /verify negatives when a resource is given)
x402-conformance facilitator https://facilitator.example --resource https://api.example.com/premium-data

# Discovery / Bazaar checks
x402-conformance discovery https://facilitator.example

# Machine-readable output + CI-friendly exit code (1 on major/critical failure)
x402-conformance check https://api.example.com/premium-data --json report.json --markdown report.md
```

Exit codes: `0` conformant, `1` not conformant (a major/critical check failed), `2` target unreachable.

## Development

```bash
pytest          # the suite's own tests (offline, mocked transport) — 102 tests
mypy            # strict type checking

# Calibrate the checks against a verify-capable reference server:
python tools/calibration_target.py 4500 &
x402-conformance check http://127.0.0.1:4500/data --active
x402-conformance facilitator http://127.0.0.1:4500 --resource http://127.0.0.1:4500/data

# One-shot live verification of the report-schema / EIP-55 / leak / extreme-amount
# features (spins the target up in each bug mode and asserts each check catches it):
python tools/verify_new_features.py
```

Live-verification runbook: [`docs/verify-new-features.md`](docs/verify-new-features.md).

No mainnet funds are ever used. Payment-flow tests run against Base Sepolia or mocks only.

## License

Apache-2.0
