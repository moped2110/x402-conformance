# Reporting & robustness features (2026-06-12)

Detailed documentation for four capabilities added on 2026-06-12: a versioned
JSON report contract (T-07), EIP-55 checksum validation (T-12), content-leak
detection on the rejection path (T-15), and extreme-amount robustness (T-16).
All four are offline-testable and need no chain.

See also [`architecture.md`](architecture.md) §3a (leak detection) and §5
(report contract) for the diagrams.

---

## 1. Versioned JSON report contract (T-07)

### What
The `--json` output of every command is now a **pinned, versioned contract**
described by [`../report.schema.json`](../report.schema.json) (JSON Schema draft
2020-12). The report gained a top-level `reportVersion` field.

### Why
The JSON report is the integration surface for anything downstream — CI gates,
dashboards, a future monitoring layer. Without a published schema, consumers
parse an ad-hoc shape that can drift silently between releases and break them.
A versioned schema turns the report into a stable API: consumers pin a major
version, and any accidental shape change fails *our* CI before it ships.

### Shape
```jsonc
{
  "reportVersion": "1.0",
  "tool":        { "name": "x402-conformance", "version": "0.1.0" },
  "specBaseline": "x402 Protocol v2 — x402-foundation/x402 @ d454eb9 (2026-06-08)",
  "target":       "https://api.example.com/premium-data",
  "timestamp":    "2026-06-12T10:00:00+00:00",
  "summary":      { "total": 21, "passed": 18, "failed": 1, "skipped": 2, "errors": 0 },
  "conformant":   false,
  "results": [
    {
      "check_id": "RS-HS-001",
      "title":    "Unpaid request is answered with HTTP 402",
      "severity": "major",          // critical | major | minor
      "spec_ref": "transports-v2/http.md §Payment Required Signaling",
      "status":   "pass",           // pass | fail | skip | error
      "detail":   ""
    }
  ]
}
```

The schema is strict: `additionalProperties: false` on every object, and
`severity`/`status` are constrained to their enums. A typo'd field name or a
stray enum value is a validation error.

### Versioning policy
`reportVersion` is `MAJOR.MINOR`, defined in `report.py` as `REPORT_VERSION`.

- **MINOR** bump — additive, backward-compatible change (e.g. a new optional
  field). Existing consumers keep working.
- **MAJOR** bump — a breaking change (field removed/renamed/retyped, an enum
  value removed). Consumers must adapt.

Pin a major in your consumer: accept `reportVersion` starting `1.`.

### Usage
```bash
x402-conformance check https://api.example.com/premium-data --json report.json
```
```python
import json, jsonschema
doc    = json.load(open("report.json"))
schema = json.load(open("report.schema.json"))
jsonschema.validate(doc, schema)          # raises on any contract drift
assert doc["reportVersion"].startswith("1.")
```

### How it's guarded
`tests/test_report.py` validates real `to_json()` output against the published
schema and asserts the schema *rejects* an out-of-enum severity — so the schema
and the emitter can't drift apart unnoticed. `jsonschema` is in the `[dev]` extra.

---

## 2. EIP-55 checksum validation — RS-PR-008 (T-12)

### What
`RS-PR-008` previously checked only that an EVM `asset` matched the address
*format* (`0x` + 40 hex). It now validates the **EIP-55 mixed-case checksum**.

### The rule (and why it's nuanced)
EIP-55 encodes a checksum in the *case* of the hex letters of an address. Three
cases:

| Address form | Meaning | Verdict |
|--------------|---------|---------|
| **Mixed-case** (`0x036CbD…F7e`) | Carries a checksum that must verify | FAIL if the checksum is wrong |
| **All-lowercase** (`0x036cbd…f7e`) | Unchecksummed — a legitimate, common form | PASS (nothing to verify) |
| **All-uppercase** | Unchecksummed | PASS (nothing to verify) |

Only a **mixed-case address with an invalid checksum** is a real defect: it's
almost always a corrupted address (a flipped bit / a typo), and sending funds to
a mistyped address loses them. Lowercase addresses are *not* flagged — many
systems legitimately emit them, and treating them as failures would be a false
positive.

### Dependency handling
EIP-55 needs keccak-256, which the standard library doesn't provide (Python's
`hashlib.sha3_256` is NIST SHA3, *not* Ethereum keccak). The check imports
`eth_utils.is_checksum_address` (pulled in by the `[evm]` extra). If keccak isn't
installed, RS-PR-008 **falls back to the format-only check** and says so in its
detail — the dependency-light passive core never hard-depends on keccak.

### Examples
```
asset 0x036CbD53842c5426634e7929541eC2318f3dCF7e  → PASS (EIP-55 checksum valid)
asset 0x036cbd53842c5426634e7929541ec2318f3dcf7e  → PASS (lowercase, unchecksummed)
asset 0x036CbD53842c5426634e7929541eC2318f3dCF7E  → FAIL (mixed-case, bad checksum)
```

---

## 3. Content-leak detection — `--resource-marker` (T-15, RS-SEC-009 path)

### What
A new `check --active --resource-marker <string>` option. Pass a unique string
that appears **only in the paid resource**; if any active negative check gets a
correctly-rejected response (non-2xx) whose **body still contains that string**,
it's flagged as a content leak.

### Why
The baseline leak guard (`_assert_rejected`) already fails an endpoint that
*serves* the resource (2xx) for an invalid payment. But a subtler bug exists: an
endpoint returns `402`/`400` (looks like a correct rejection) yet still includes
the protected content in the error body — e.g. a template that renders the
resource before the paywall verdict, or a verbose error echoing upstream output.
Status-code checking alone misses this. The marker catches it.

### How it works
The marker is checked **once, centrally**, where responses are built — the
`send`/`send_header` closures in `build_active_context` already hold the marker
in scope. A match sets a single `marker_leaked` flag on the (frozen)
`ActiveResponse`; `_assert_rejected` reads that flag and fails with a clear
detail. No per-check wiring: all active checks gain leak detection for free.

```
ActiveResponse(status_code=402, …, marker_leaked=True)
  → RS-NEG-00x FAIL: "status 402 but the response body contained the resource
                      marker — protected content leaked on the rejection path"
```

### Usage & guidance
```bash
x402-conformance check https://api.example.com/premium-data \
    --active --resource-marker "x7f3-caviar-recipe-42"
```
- Choose a marker that's **specific** to the paid content and won't appear in a
  normal error page (a long random token, a unique phrase from the resource).
- **Prefer an ASCII marker.** The body is searched for the marker's raw UTF-8
  bytes; if a server re-encodes the body and escapes non-ASCII (e.g. JSON turns
  `§` into `§`), a non-ASCII marker may not match even though the content is
  present. ASCII markers are immune.
- The flag is optional; omit it and behaviour is unchanged.
- It complements, not replaces, the 2xx/settlement leak guard — both run.

### Verifying it live
`tools/calibration_target.py --bug-leak` echoes the marker on its rejection path,
and `tools/verify_new_features.py` asserts the check catches it (see the runbook
[`verify-new-features.md`](verify-new-features.md)).

---

## 4. Extreme-amount robustness — RS-SEC-011 (T-16)

### What
A new active check (`check --active`) that signs a payment for a **`2²⁵⁶-1`**
(uint256 max) amount and submits it.

### Why
A huge amount probes two failure modes at once:

1. **Tooling overflow** — building/signing the EIP-712 authorization must handle
   a uint256-max value without overflowing (Python big ints do; this proves the
   payload path doesn't truncate).
2. **Endpoint robustness** — a naive backend that parses the amount into a
   fixed-width integer, or does unchecked arithmetic, can **crash (5xx)** on an
   absurd value. A conformant endpoint rejects it *cleanly*.

### Verdict
| Endpoint response | Verdict | Reason |
|-------------------|---------|--------|
| `5xx` | **FAIL** | crashed on a huge value (robustness bug) |
| 2xx / settled | **FAIL** | accepted a `2²⁵⁶-1` payment (validation bug) |
| clean non-2xx rejection | **PASS** | handled cleanly |

Severity is **minor** (robustness), not critical — it's a quality signal, not a
funds-at-risk finding like the underpayment/recipient checks.

---

## Summary

| Task | Capability | Surface | Severity / kind |
|------|-----------|---------|-----------------|
| T-07 | Versioned JSON report contract | `report.schema.json`, `reportVersion` | tooling contract |
| T-12 | EIP-55 checksum validation | `RS-PR-008` (passive) | minor |
| T-15 | Content-leak on rejection path | `--resource-marker` → all RS-NEG | critical when it fires |
| T-16 | Extreme-amount robustness | `RS-SEC-011` (active) | minor |

All four ship with tests (102 offline tests total, mypy strict clean) and need no
chain or funds.
