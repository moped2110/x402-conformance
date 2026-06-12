# Architecture — how x402-conformance works

Black-box conformance tester for [x402](https://github.com/x402-foundation/x402) V2
endpoints. You point it at a URL; it probes the endpoint, evaluates a catalog of
spec-traceable checks, and emits a verdict + report. Every check carries an ID,
severity, and a spec reference (see [`conformance-catalog.md`](conformance-catalog.md)).

## 1. The big picture — commands and check groups

```mermaid
flowchart TD
    user([User / CI]) --> cli["x402-conformance CLI<br/>(Typer)"]

    cli --> chk["check &lt;url&gt;"]
    cli --> fac["facilitator &lt;url&gt;"]
    cli --> disc["discovery &lt;url&gt;"]
    cli --> ver["version"]

    chk -->|always, passive| RUN["run_checks()<br/>2 unpaid requests"]
    chk -->|--active| ACT["run_active_checks()<br/>tampered payments"]
    chk -->|--pay 💸| PAY["run_payment_checks()<br/>1 funded on-chain settle"]

    RUN --> G_HS["RS-HS · handshake<br/>RS-PR · PaymentRequired schema<br/>(RS-PR-008 · EIP-55)"]
    ACT --> G_NEG["RS-NEG · negative<br/>RS-SEC-010 · cross-chain replay<br/>RS-SEC-011 · extreme amount<br/>--resource-marker · leak"]
    PAY --> G_PAY["RS-PAY · positive settle<br/>RS-SEC-001/002 · replay/race"]

    fac --> G_FA["FA-SUP /supported<br/>FA-VER /verify · FA-ERR<br/>FA-SET /settle 💸 (--settle)"]
    disc --> G_DI["DI · /discovery/resources"]

    G_HS --> REP
    G_NEG --> REP
    G_PAY --> REP
    G_FA --> REP
    G_DI --> REP

    REP["report.py<br/>summarize · exit_code · to_json · to_markdown"]
    REP --> OUT([stdout + JSON/MD<br/>exit 0 conformant · 1 fail · 2 unreachable])

    classDef pay fill:#ffe6e6,stroke:#cc0000;
    class PAY,G_PAY pay;
```

`💸` = moves real funds → testnet/Anvil only, opt-in behind an explicit flag.

## 2. Passive check pipeline (`check`, no payment)

Two unpaid requests are made, then each response is *pre-digested* in stages so a
check can pinpoint the exact failure layer (bad base64 vs. bad JSON vs. schema).

```mermaid
flowchart LR
    A["httpx client<br/>2× unpaid request"] --> B["build_probe()"]

    subgraph decode["staged decode (errors recorded, never raised)"]
        B --> C["PAYMENT-REQUIRED<br/>header present?"]
        C --> D["base64 decode<br/>↳ decode_error"]
        D --> E["JSON parse<br/>↳ json_error"]
        E --> F["PaymentRequired schema<br/>(pydantic) ↳ parse_error"]
    end

    F --> G["ProbeSession<br/>(first, second)"]
    G --> H["REGISTRY checks<br/>RS-HS-00x · RS-PR-00x"]
    H --> I["CheckResult[]<br/>PASS / FAIL / SKIP / ERROR"]
```

Key design rule: **a check never raises on bad endpoint behavior** — it returns
`FAIL`/`SKIP` with a detail string. A crash is classified `ERROR` and treated as a
bug in the suite, never the target's fault.

## 3. Active negative pipeline (`check --active`)

Signs a *valid* EIP-3009 `TransferWithAuthorization`, then mutates exactly one
field per test so the endpoint is forced to reject for one specific reason.

```mermaid
sequenceDiagram
    participant R as run_active_checks
    participant Ctx as build_active_context
    participant PB as payload_builder<br/>(eth-account)
    participant EP as Target endpoint

    R->>Ctx: probe endpoint, pick exact/eip3009 requirement
    Ctx-->>R: ActiveContext (send / send_header)
    loop each RS-NEG check
        R->>PB: build valid signed payload
        PB-->>R: payload (EIP-712 signature)
        R->>PB: tamper ONE field<br/>(sig / value / recipient / time / asset / chainId)
        R->>EP: send PAYMENT-SIGNATURE: base64(payload)
        EP-->>R: response
        Note over R: PASS only if endpoint REJECTS<br/>(no 2xx, no settled_ok)
    end
```

Independence guarantee: signing is built directly on `eth-account`, **not** the
x402 SDK — so the tester can't inherit the SDK's bugs. The SDK is used only as a
test-time oracle (the EIP-712 digest is asserted byte-identical in the unit tests).
Throwaway random signer by default; no funds, no chain needed.

The same pipeline also runs two robustness/security checks that don't fit the
"tamper one field" mould:

- **RS-SEC-010** — signs for a *different* `chainId` (`eip155:1`) but submits to
  this endpoint; EIP-712 binds chainId in the domain, so recovery must fail.
- **RS-SEC-011** — signs a `2²⁵⁶-1` (uint256 max) amount. The tool must sign it
  without overflow and the endpoint must reject it *cleanly* — a `5xx` here means
  the endpoint crashed on a huge value (FAIL), not that it validated it.

### 3a. Content-leak detection on the rejection path (`--resource-marker`)

Every active check already fails an endpoint that *serves* the resource (2xx) or
reports a successful settlement for an invalid payment. `--resource-marker`
strengthens this: it catches an endpoint that correctly returns a non-2xx **but
still leaks the protected content in the error body**.

```mermaid
flowchart LR
    M["--resource-marker 'SECRET'"] --> Ctx["build_active_context<br/>marker_bytes in closure"]
    Ctx --> S["send() / send_header()"]
    S --> R["endpoint response"]
    R --> Chk{"marker in<br/>body?"}
    Chk -->|yes| Leak["ActiveResponse(marker_leaked=True)"]
    Chk -->|no| OK["ActiveResponse(marker_leaked=False)"]
    Leak --> A["_assert_rejected → FAIL<br/>'content leaked on rejection path'"]
    OK --> A2["_assert_rejected → normal verdict"]
```

Design choice: the leak is detected **once, centrally**, at response-build time
inside the `send`/`send_header` closures (which already hold the marker in
scope), and exposed as a single `marker_leaked` flag on `ActiveResponse`. So all
~11 negative checks gain leak detection without touching a single call site —
`_assert_rejected` just reads the flag.

## 4. Positive settlement pipeline (`check --pay` 💸)

```mermaid
sequenceDiagram
    participant R as run_payment_checks
    participant EP as Target endpoint
    participant Chain as RPC (web3, opt-in)

    R->>R: build ONE valid funded payload
    R->>EP: send payment
    EP-->>R: 2xx + PAYMENT-RESPONSE (settlement)
    Note over R: RS-PAY-001 resource served<br/>RS-PAY-002 settlement valid<br/>RS-PAY-003 network/payer match
    opt --rpc-url given
        R->>Chain: get_transaction_receipt(tx)
        Chain-->>R: status 1 → RS-PAY-004 PASS
    end
    R->>EP: replay same nonce → must reject (RS-SEC-001)
    R->>EP: 5× concurrent → ≤1 success (RS-SEC-002)
```

All assertions share a **single** settlement (one nonce, one on-chain tx) so the
group never spends per-check.

## 5. Report output contract (versioned JSON)

Every command funnels its `CheckResult[]` through `report.py`, which produces the
terminal summary, the CI exit code, an optional Markdown report, and an optional
**machine-readable JSON report** whose shape is a pinned contract.

```mermaid
flowchart LR
    CR["CheckResult[]"] --> RP["report.py"]
    RP --> SUM["summarize() → counts"]
    RP --> EC["exit_code() → 0/1"]
    RP --> MD["to_markdown()"]
    RP --> JS["to_json()<br/>reportVersion + summary + results[]"]
    JS -. "validated in CI" .-> SCH["report.schema.json<br/>(JSON Schema 2020-12)"]
    EC --> EX(["process exit code<br/>0 conformant · 1 fail · 2 unreachable"])
```

The JSON carries a top-level `reportVersion` (currently `1.0`). `report.schema.json`
at the repo root is the published contract — `additionalProperties: false`,
`severity`/`status` constrained to enums — and the test suite validates real
output against it, so any accidental shape drift fails CI. Consumers pin a major
version of `reportVersion`.

| Field | Meaning |
|-------|---------|
| `reportVersion` | Schema version of this report shape (`MAJOR.MINOR`). |
| `tool` | `{name, version}` of the tester. |
| `specBaseline` | Pinned x402 spec snapshot the checks target. |
| `target` | The tested endpoint / base URL. |
| `timestamp` | UTC ISO-8601 generation time. |
| `summary` | `{total, passed, failed, skipped, errors}`. |
| `conformant` | `true` when no critical/major check failed/errored. |
| `results[]` | One `{check_id, title, severity, spec_ref, status, detail}` per check. |

## 6. Module map

```mermaid
flowchart TD
    cli[cli.py] --> runner[runner.py]
    cli --> active[active.py]
    cli --> report[report.py]
    cli --> fac[checks/facilitator.py]
    cli --> disc[checks/discovery.py]

    runner --> probe[probe.py]
    runner --> registry[checks/base.py · REGISTRY]
    probe --> models[models.py · pydantic schemas]

    registry --> hs[checks/handshake.py · RS-HS]
    registry --> pr[checks/payment_required.py · RS-PR<br/>RS-PR-008 → eth_utils EIP-55]

    active --> probe
    active --> neg[checks/negative.py · RS-NEG<br/>RS-SEC-010/011 · marker leak]
    active --> payc[checks/payment.py · RS-PAY]
    neg --> builder[payload_builder.py · eth-account]
    payc --> builder
    fac --> builder

    report --> models
    report -. "validated against" .-> schema[report.schema.json]
    pr -. "optional keccak" .-> ethutils[eth_utils]
```

The `[evm]` extra (eth-account, eth-utils) is only needed for `--active`/`--pay`,
the facilitator `/verify` negatives, and RS-PR-008's EIP-55 checksum validation;
the `[onchain]` extra (web3) only for RS-PAY-004. The passive core stays
dependency-light and chain-free — RS-PR-008 falls back to a format-only check
when keccak isn't installed, so the core never hard-depends on it.
