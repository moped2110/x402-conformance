# x402-conformance

Black-box conformance and robustness testing for [x402](https://github.com/x402-foundation/x402) payment endpoints.

Point it at any x402-paywalled URL and get a spec-traceable report: does the 402 handshake conform to the x402 V2 protocol? Are payment requirements well-formed? Does the endpoint reject what it must reject?

**Spec baseline:** x402 Protocol v2, `x402-foundation/x402` @ `d454eb9` (2026-06-08).
**Test catalog:** see [`docs/conformance-catalog.md`](docs/conformance-catalog.md) — every check carries an ID, severity, and spec reference.

## Status

Working tool, early version. Implemented check groups:

- **RS-HS** (handshake) and **RS-PR** (PaymentRequired schema) — passive, no payment.
- **RS-NEG** + **RS-SEC-010** (negative / security) — `--active`: signs deliberately-invalid payments and verifies the endpoint rejects them. Throwaway signer, no funds, no chain needed.
- **FA** (facilitator `/supported`, `/verify`) — the `facilitator` command.
- **DI** (discovery / Bazaar) — the `discovery` command.

- **RS-PAY** + **RS-SEC-001** (positive settlement + replay) — `check --pay`: signs a valid funded payment, settles it ON-CHAIN, verifies the tx, and confirms a replay is rejected. Confirmed live against Anvil.
- **FA-SET** (facilitator `/settle`) — `facilitator --settle`: valid settle, invalid settle, double-settle.

Calibrated against a verify-capable reference target (`tools/calibration_target.py`) and confirmed end-to-end on a local chain (Anvil + `onchain/MockUSDC.sol`, a faithful EIP-3009 token). See `docs/onchain-2026-06-11.md`. 38 checks across 5 groups; 94 offline tests.

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
pytest          # the suite's own tests (offline, mocked transport) — 85 tests
mypy            # strict type checking

# Calibrate the checks against a verify-capable reference server:
python tools/calibration_target.py 4500 &
x402-conformance check http://127.0.0.1:4500/data --active
x402-conformance facilitator http://127.0.0.1:4500 --resource http://127.0.0.1:4500/data
```

No mainnet funds are ever used. Payment-flow tests run against Base Sepolia or mocks only.

## License

Apache-2.0
