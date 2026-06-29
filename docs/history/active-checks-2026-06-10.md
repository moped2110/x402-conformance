# RS-NEG Active Checks — Status & Calibration (2026-06-10)

## What shipped
The active negative-test group (`--active`) is implemented: the suite builds a
real EIP-3009 payment with a throwaway signer, breaks exactly one thing, sends
it via the `PAYMENT-SIGNATURE` header, and asserts the endpoint rejects it.

**11 active checks:** RS-NEG-001 (garbage base64), -002 (malformed JSON),
-003 (tampered signature), -005 (underpayment), -006 (overpayment),
-007 (recipient mismatch), -008 (expired), -009 (not-yet-valid),
-013 (client-claimed lower price), -014 (wrong asset), and RS-SEC-010
(cross-chain signature replay).

Run with: `x402-conformance check <url> --active`. A throwaway signer is used by
default (or `$X402_TESTNET_PAYER_KEY` / `--signer-key`). No mainnet, ever.

## Why this needs no funded payer
A correct server rejects every one of these at the **verification step**, before
any on-chain settlement. So the negative group runs against a verify-capable
endpoint without funding the signer. Only the *positive* path (RS-PAY-004, real
settlement) needs a funded payer — that is the separate T-09 work.

## Verification done (three layers)
1. **Offline unit tests** (`tests/test_negative.py`) against a configurable mock
   server: a fully correct server → all 11 checks PASS (zero false positives);
   servers missing a specific validation → the matching check FAILs (it catches
   the bug). Notably RS-NEG-013 is the *only* check that catches a server which
   verifies signatures but forgets to validate the price — proving its distinct
   value.
2. **Live end-to-end smoke test** over a real HTTP socket (not MockTransport):
   CLI `--active` against a locally-run correct server → all 10 signed/active
   checks PASS, combined report 30 passed / 0 failed / 1 skip.
3. **Keystone** (from T-02): our EIP-712 digest is byte-identical to the
   reference SDK, so the payments we sign are genuinely spec-valid.

## Live calibration — DONE (2026-06-10), non-circular
`tools/calibration_target.py` is a verify-capable reference server that
validates payments using the **x402 SDK's own EIP-712 digest**
(`hash_eip3009_authorization`) plus the same scheme/recipient/amount/timing
rules as the SDK facilitator's `verify` (RPC-bound steps — balance, `get_code`,
simulation — omitted; negatives never reach them). Because the suite signs
independently (eth-account) and the target verifies with SDK primitives, a green
run is a genuine cross-implementation calibration, not a self-check.

Results (CLI `--active` over a real HTTP socket):
- **Correct server → 31 passed, 0 failed, 1 skipped** (skip = RS-PR-011, no
  extensions advertised). Zero false positives across all 11 active checks.
- **`--bug-no-signature` →** RS-NEG-003, RS-NEG-014, RS-SEC-010 correctly FAIL
  (these depend on signature verification).
- **`--bug-no-amount` →** RS-NEG-013 and RS-NEG-006 correctly FAIL, while
  RS-NEG-005 stays PASS (its post-signing tamper is caught by the signature
  check) — proving RS-NEG-013 is the unique catch for a price-validation gap.

Reproduce:
```
python tools/calibration_target.py 4500 &
x402-conformance check http://127.0.0.1:4500/data --active
```

## Still open (needs RPC / chain — T-09 settlement work)
The calibration target omits the RPC-bound verification steps (on-chain
balance, asset `get_code`, transfer simulation) and never settles. The
**positive path (RS-PAY-004, real settlement)** and the **balance-dependent
rejection** still need a funded Base Sepolia payer or a local Anvil chain.
`tools/calibration_target.py` is built to grow into a full facilitator by
swapping in an RPC-backed signer.

## Not yet covered (next)
- RS-SEC-001/002/003 (replay-after-settlement, parallel race, cross-resource):
  need real settlement or stateful endpoint → after T-09.
- RS-SEC-011 (overflow robustness), RS-NEG content-leak body inspection.
- FA-* facilitator direct checks (T-06).
