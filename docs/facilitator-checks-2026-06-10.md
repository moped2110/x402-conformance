# FA Facilitator Checks — Status (2026-06-10)

## What shipped
A facilitator check group (`checks/facilitator.py`) with its own CLI command:

```
x402-conformance facilitator <facilitator_url> [--resource <x402_url>]
```

**4 checks (chain-free):**
- **FA-SUP-001** — `GET /supported` returns `kinds[]`, `extensions[]`, `signers{}` (correct types).
- **FA-SUP-002** — every kind has `x402Version == 2`, a `scheme`, and a CAIP-2 `network`.
- **FA-VER-002** — `POST /verify` with a validly-signed payment whose `value` ≠ the required amount must return `isValid: false`. (Re-signed for the low amount, *not* a post-signing tamper — otherwise the signature check masks an amount-validation gap; cf. RS-NEG-013.)
- **FA-ERR-001** — the returned `invalidReason` is from the CORE §9 error registry.

FA-SUP run on the facilitator URL alone. FA-VER/FA-ERR need `--resource` (an x402
endpoint) to source real requirements, plus a throwaway signer.

## Calibration (non-circular, via `tools/calibration_target.py`)
The calibration target now also serves `/supported` and `/verify` (verifying with
the SDK EIP-712 digest). Results over a real socket:
- **Correct facilitator → 4 passed, 0 failed.**
- **`--bug-no-amount` →** FA-VER-002 and FA-ERR-001 correctly FAIL (it accepts
  `value != requirements.amount`).
- **`--bug-no-signature` →** FA-VER-002 correctly stays PASS (the amount check
  catches the low-value payment) — no false negative.

Reproduce:
```
python tools/calibration_target.py 4500 &
x402-conformance facilitator http://127.0.0.1:4500 --resource http://127.0.0.1:4500/data
```

## Deferred to on-chain day (need RPC / funded payer)
- FA-VER-001 (valid payload → `isValid:true`; a real facilitator checks balance).
- FA-VER-003 (verify does not settle — needs chain state observation).
- FA-SET-001/002 (`/settle`), FA-SET-003 (double-settle / nonce reuse).

## Still-open passive gaps (next, no chain needed)
- **DI-001/002** — `GET /discovery/resources` schema + filter honoring (Bazaar).
- **RS-SEC-011** — extreme/near-2²⁵⁶ amount robustness (active-ish: send huge value, endpoint must respond cleanly).
- **RS-PR-011** — validate extension `info` against its declared `schema` (currently structural only).
