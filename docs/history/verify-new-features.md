# Runbook — verifying the 2026-06-12 features live

How to verify the four features (T-07 report schema, T-12 EIP-55, T-15
content-leak marker, T-16 extreme-amount) against a real server. Three layers,
fastest first.

Features and the diagrams: [`reporting-and-robustness-2026-06-12.md`](reporting-and-robustness-2026-06-12.md)
and [`../architecture.md`](../architecture.md).

Prereqs for the live layers: the x402 SDK and `eth-account` installed (the
calibration deps). `pip install -e ".[dev]"` covers `eth-account`, `web3`,
`jsonschema`; the x402 SDK is a separate local install.

---

## Layer 1 — offline unit tests (no server, runs anywhere)

Already part of the suite; proves the logic with mocked transports.

```bash
pytest -q
# Relevant tests:
#   tests/test_report.py            → schema validation + reportVersion (T-07)
#   tests/test_payment_required.py  → RS-PR-008 EIP-55 valid / bad / lowercase (T-12)
#   tests/test_negative.py          → RS-SEC-011 + --resource-marker leak (T-15/T-16)
```

## Layer 2 — automated live verification (one command)

Spins up the calibration target over real HTTP in several modes and drives the
actual suite against it, asserting each check PASSes a correct server and CATCHes
the matching bug. CI-style exit code.

```bash
python tools/verify_new_features.py
# → one line per case, then:
#   VERIFICATION OK — all new-feature expectations hold against a live server.
```

What it asserts:

| Mode | Expectation |
|------|-------------|
| correct server | RS-PR-008 PASS · RS-SEC-011 PASS · no active false-positives · report validates against schema |
| `--bug-bad-checksum` | RS-PR-008 **FAIL** (catches the broken EIP-55 checksum) |
| `--bug-crash-huge` | RS-SEC-011 **FAIL** (catches the 5xx crash on a 2²⁵⁶-1 amount) |
| `--bug-leak` | a negative check **FAILs** with a marker leak; and *without* `--resource-marker` the same server looks clean (proving the flag is what catches it) |

## Layer 3 — manual calibration target (see the CLI output yourself)

Run the target in one terminal, the CLI in another.

```bash
# Terminal A — correct server
python tools/calibration_target.py 4500

# Terminal B
x402-conformance check http://127.0.0.1:4500/data --active \
    --resource-marker x402-calib-marker-7f3a --json report.json
#   → all PASS; RS-PR-008 PASS (valid EIP-55), RS-SEC-011 PASS

python -c "import json,jsonschema; jsonschema.validate(json.load(open('report.json')), json.load(open('report.schema.json'))); print('schema OK')"
```

Now the bug modes — each must turn exactly one check red:

```bash
python tools/calibration_target.py 4500 --bug-bad-checksum
x402-conformance check http://127.0.0.1:4500/data
#   → RS-PR-008 FAIL: bad EIP-55 checksum

python tools/calibration_target.py 4500 --bug-crash-huge
x402-conformance check http://127.0.0.1:4500/data --active
#   → RS-SEC-011 FAIL: crashed on an extreme amount

python tools/calibration_target.py 4500 --bug-leak
x402-conformance check http://127.0.0.1:4500/data --active --resource-marker x402-calib-marker-7f3a
#   → a negative check FAILs: protected content leaked on the rejection path
```

The pre-existing validation bugs still apply too, e.g.
`--bug-no-amount`, `--bug-no-signature`, `--bug-no-recipient`, `--bug-no-time`.

## Layer 4 — against your own reference server (this evening)

Point the suite at your local x402 endpoint. Everything but the marker works with
no extra setup:

```bash
URL=http://127.0.0.1:<your-port>/<resource>

# Passive + EIP-55 (T-12) + report schema (T-07):
x402-conformance check "$URL" --json report.json
python -c "import json,jsonschema; jsonschema.validate(json.load(open('report.json')), json.load(open('report.schema.json'))); print('schema OK')"

# Active incl. RS-SEC-011 extreme amount (T-16):
x402-conformance check "$URL" --active

# Content-leak (T-15): pass a string that appears ONLY in the paid resource.
# Use an ASCII marker (raw-byte match; non-ASCII can be JSON-escaped server-side).
x402-conformance check "$URL" --active --resource-marker "<unique-string-from-the-paid-body>"
```

Expected against a correct server: RS-PR-008 PASS (real USDC is checksummed),
RS-SEC-011 PASS, no marker leak, report validates against the schema. Any FAIL is
a real finding — capture the `--json` report.
