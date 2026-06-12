# Changelog

All notable changes to x402-conformance are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- **RS-SEC-011** (`check --active`): extreme/near-2²⁵⁶ amount robustness — the
  endpoint must reject a uint256-max amount cleanly without a 5xx crash.
- **`--resource-marker`** for `check --active`: pass a unique string from the
  protected resource; a rejected response whose body still contains it is flagged
  as a content leak (RS-SEC-009 on the rejection path).
- **`report.schema.json`**: a versioned JSON Schema for the `--json` report
  output, with a `reportVersion` field; CI validates the output against it.

### Changed
- **RS-PR-008** now performs full EIP-55 checksum validation on mixed-case EVM
  asset addresses (via keccak when `[evm]` is installed); all-lowercase
  addresses remain a valid unchecksummed form. Previously format-only.
- **RS-SEC-011** also flags a resource-marker leak on the extreme-amount
  rejection path (consistent with the other active checks).
- `check` warns when `--resource-marker` is passed without `--active` (no effect).

### Tests / tooling
- Catalog↔code drift guard: tests assert every implemented check ID appears in
  `conformance-catalog.md` and that its "Implemented & tested (N)" count matches
  the code (covers registry-less RS-PAY/FA-SET groups too).
- Stricter report-schema tests (format-checked timestamp, rejects unknown
  status, additional properties, and missing required fields).
- `tools/verify_new_features.py` + `--bug-leak`/`--bug-crash-huge`/
  `--bug-bad-checksum` modes in the calibration target for live verification.

## [0.1.0] — 2026-06-11

First working release. Black-box conformance testing for x402 V2 payment
endpoints, from the 402 handshake through real on-chain settlement.

**Spec baseline:** x402 Protocol v2, `x402-foundation/x402` @ `d454eb9` (2026-06-08).

### Added
- **Passive checks** (`check`): RS-HS-001…007 (handshake) and RS-PR-001…014
  (PaymentRequired schema), including cache-control, CAIP-2 namespace
  consistency, and strictly-positive amount.
- **Active negative checks** (`check --active`): RS-NEG-001/002/003/005/006/007/
  008/009/013/014 and RS-SEC-010 (cross-chain signature replay). Independent
  EIP-3009 signing (eth-account), proven byte-identical to the reference SDK.
- **On-chain settlement** (`check --pay`): RS-PAY-001…004 (positive path + tx
  verification) plus RS-SEC-001 (replay) and RS-SEC-002 (concurrent race).
- **Facilitator checks**: `facilitator` (FA-SUP-001/002, FA-VER-002, FA-ERR-001)
  and `facilitator --settle` (FA-SET-001/002/003, incl. double-settle).
- **Discovery checks** (`discovery`): DI-001/002.
- **CLI**: `check`, `facilitator`, `discovery`, `version`; JSON + Markdown
  reports; CI-friendly exit codes (0 conformant, 1 not, 2 unreachable).
- **On-chain harness** (`onchain/`, `tools/`): `MockUSDC.sol` (faithful EIP-3009
  token with on-chain signature verification + nonce tracking),
  `onchain_facilitator.py` (real web3 settlement), `calibration_target.py`
  (verify-capable reference), `onchain_smoke.py` (end-to-end smoke test).
- 94 offline tests (httpx MockTransport), mypy strict clean, GitHub Actions CI
  on Python 3.11/3.12/3.13.

### Verified
- Calibrated against a verify-capable reference target (non-circular: suite
  signs independently, target verifies with SDK primitives) — zero false
  positives; deliberately-buggy variants caught.
- Full on-chain block confirmed live against local Anvil (chain-id 84532): real
  settlements, real funds moving, replay/race/double-settle all rejected.

### Known limitations
- Settlement checks need an EVM testnet (Anvil or Base Sepolia) and a funded
  signer; the core passive suite is chain-free.
- Planned-but-unshipped checks are listed in `docs/conformance-catalog.md`.

[0.1.0]: https://github.com/x402-foundation/x402
