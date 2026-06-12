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

    RUN --> G_HS["RS-HS · handshake<br/>RS-PR · PaymentRequired schema"]
    ACT --> G_NEG["RS-NEG · negative<br/>RS-SEC-010 · cross-chain replay"]
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

## 5. Module map

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
    registry --> pr[checks/payment_required.py · RS-PR]

    active --> probe
    active --> neg[checks/negative.py · RS-NEG]
    active --> payc[checks/payment.py · RS-PAY]
    neg --> builder[payload_builder.py · eth-account]
    payc --> builder
    fac --> builder

    report --> models
```

The `[evm]` extra (eth-account) is only needed for `--active`/`--pay` and the
facilitator `/verify` negatives; the `[onchain]` extra (web3) only for RS-PAY-004.
The passive core stays dependency-light and chain-free.
