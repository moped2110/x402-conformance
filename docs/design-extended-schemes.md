# Design sketch — extended scheme coverage (T-11)

How to teach the active/settlement checks two more payment mechanisms beyond
EVM/EIP-3009: **EVM permit-style** (EIP-2612 / Permit2) and runnable **SVM
`exact`** (Solana). This is a forward-looking design; the authoritative current
boundary is [`support-matrix.md`](support-matrix.md).

**Status today:** the EVM active group is hardcoded to one mechanism. The gate is
`choose_eip3009_requirement` (in `active.py`): `scheme == "exact"` **and**
`network` starts with `eip155:` **and** `extra.assetTransferMethod == "eip3009"`.
Each `RS-NEG` check calls `build_exact_eip3009_payload(...)` then a `tamper_*`
from `payload_builder.py`. The SVM foundation now ships CAIP-2 handling, ATA
derivation, a spec-shaped partial-transaction builder, and tamper primitives in
`svm.py`; it still has no runnable check group or settlement proof. Shared HTTP
checks can inspect other rails only at the passive envelope level.

---

## Why this work, by asset

The suite doesn't care about a coin's *brand* — only about two axes: the
**network family** (`eip155:` / `solana:` / other) and the **transfer/authorization
method** (`extra.assetTransferMethod`). The same asset on a different chain or with
a different method lands in a different mechanism.

| Asset | Typical x402 setup | Today | Needs |
|-------|--------------------|-------|-------|
| **USDC** (EVM) | `exact` / **EIP-3009** | ✅ full active + settlement | — (happy path) |
| **EURC** (EVM) | `exact` / **EIP-3009** (same Circle template) | ✅ full active + settlement | — (works today) |
| **USDC** (Solana) | SVM `exact` | foundation/passive only; active/pay SKIP | §2 SVM runner |
| **USDT** (EVM) | `exact` / **Permit2** (no EIP-3009 on USDT) | passive ✅, active/pay SKIP | §1 permit-style |
| **EURT / other euro stables w/o EIP-3009** | `exact` / Permit2 (token-dependent) | passive ✅, active/pay SKIP | §1 permit-style |
| **Other non-USDC ERC-20** | `exact` / Permit2 | passive ✅, active/pay SKIP | §1 permit-style |
| **WBTC / wrapped BTC** (EVM) | `exact` / Permit2 (plain ERC-20) | passive ✅, active/pay SKIP | §1 permit-style |
| **XRP via XRPL-EVM sidechain** | `exact` / EIP-3009 or Permit2 | EVM → 3009 ✅ / Permit2 SKIP | — or §1 |
| **BTC native** | not an x402 scheme | passive only (if advertised) | out of scope* |
| **XRP native (XRPL)** | not an x402 scheme | passive only (if advertised) | out of scope* |

Key facts driving the priority:

- **USDC implements EIP-3009** (`transferWithAuthorization`) → it's the one asset
  that works fully today, on any EVM chain (chainId is read generically).
- **Currency is irrelevant** — the amount is an atomic integer and the asset is a
  contract address; there is no fiat/decimals logic. **EURC** uses the same Circle
  contract template as USDC and therefore also implements EIP-3009, so it works
  today unchanged. Euro stablecoins *without* EIP-3009 (e.g. Tether's EURT, and
  token-by-token others like EURe/agEUR/EURS) route through Permit2 → §1.
- **USDT does *not* implement EIP-3009** (nor EIP-2612 on Ethereum mainnet), so an
  x402 endpoint accepting USDT must use **Permit2** (which wraps arbitrary ERC-20s
  via a one-time approve + signature). The same is true for most non-USDC ERC-20s.
  **This is why §1 (permit-style) is the highest-value next step — it unlocks
  everything that isn't USDC on EVM.**
- **\*Native BTC and XRP** fall outside x402's signed-payload model entirely:
  Bitcoin is UTXO-based, XRPL has its own tx/signing format, and neither has a
  "signed authorization the server redeems" like EIP-3009/Permit. Their
  x402-relevant forms are the **wrapped / EVM-sidechain** variants, which behave
  like any ERC-20 (→ §1). Testing the *native* chains actively would be a separate,
  larger mechanism with a different threat model ("broadcast + watch-chain" rather
  than "signed payload") — not in scope for T-11.

In all cases the passive groups (`RS-HS`, `RS-PR`, `FA`, `DI`) run unchanged, and
unsupported active cases **SKIP cleanly** — so the suite never crashes or
false-fails on an asset it can't actively exercise yet.

---

## 0. Shared foundation: a `PaymentMechanism` abstraction

Both new schemes need the same refactor first, so the negative/payment checks
stop assuming EIP-3009. Introduce a mechanism interface and make the checks
mechanism-driven.

```python
# src/x402_conformance/mechanisms/base.py
from typing import Any, Protocol

class Signer(Protocol):
    """A key that can sign for one mechanism family (EVM secp256k1 / SVM ed25519)."""
    @property
    def address(self) -> str: ...

# Stable case ids decouple "what defect" from "which mechanism implements it".
class Case:
    SIGNATURE   = "signature"      # RS-NEG-003
    UNDERPAY    = "underpay"       # RS-NEG-005
    OVERPAY     = "overpay"        # RS-NEG-006
    RECIPIENT   = "recipient"      # RS-NEG-007
    EXPIRED     = "expired"        # RS-NEG-008
    NOT_YET     = "not_yet_valid"  # RS-NEG-009
    CLAIM_CHEAP = "claim_cheap"    # RS-NEG-013
    WRONG_ASSET = "wrong_asset"    # RS-NEG-014
    XCHAIN      = "xchain_replay"  # RS-SEC-010
    EXTREME     = "extreme_amount" # RS-SEC-011

class PaymentMechanism(Protocol):
    id: str                       # "evm-eip3009" | "evm-permit2" | "svm-exact"

    def matches(self, accepts_entry: dict[str, Any]) -> bool: ...
    def build_valid(self, requirements: dict[str, Any], signer: Signer) -> dict[str, Any]: ...
    def supports(self, case: str) -> bool: ...          # which defects are meaningful here
    def tamper(self, case: str, payload: dict[str, Any],
               requirements: dict[str, Any], signer: Signer) -> dict[str, Any]: ...
```

Then:

- **Registry + selection.** A `MECHANISMS: list[PaymentMechanism]` and
  `choose_mechanism(raw) -> tuple[PaymentMechanism, dict] | None` replacing
  `choose_eip3009_requirement`. `build_active_context` stores the chosen
  mechanism on `ActiveContext` (new field `mechanism`).
- **Mechanism-driven negative checks.** Replace the ~11 hand-written
  `@_register` bodies with one registration per `Case`, whose body is:
  ```python
  def _run_case(ctx, case):
      if not ctx.mechanism.supports(case):
          return Status.SKIP, f"{ctx.mechanism.id} has no '{case}' defect"
      payload = ctx.mechanism.build_valid(ctx.requirements, ctx.signer)
      bad = ctx.mechanism.tamper(case, payload, ctx.requirements, ctx.signer)
      return _assert_rejected(ctx.send(bad))
  ```
  The ID/severity/spec_ref metadata stays exactly as today; only the body is
  routed through the mechanism. `RS-NEG-001/002` (garbage base64 / bad JSON) stay
  transport-level and mechanism-independent.
- **EVM/EIP-3009 becomes the first mechanism**, wrapping today's
  `build_exact_eip3009_payload` + `tamper_*` verbatim — a pure move, no behaviour
  change, fully covered by the existing tests (the safety net for the refactor).
- **`supports()` is where schemes differ** — e.g. SVM returns `False` for
  `XCHAIN`, permit returns `False` for `NOT_YET`. Unsupported cases SKIP cleanly,
  exactly like the current Solana-only test expects.

Effort: **M** (mechanical refactor + keep tests green). This is the prerequisite;
the two mechanisms below are **M each** on top.

---

## 1. EVM permit-style — EIP-2612 & Permit2

x402 signals this with `extra.assetTransferMethod` ≠ `"eip3009"` — in practice
`"permit2"` / the `permit2-eip2612GasSponsoring` variant. Same chain family
(`eip155:`), same `EvmSigner` (secp256k1, EIP-712) — so this **reuses the
existing signer and `eth-account`**; only the typed-data struct and the
replay/recipient model change.

### Gate
```python
def matches(self, e):
    return (e.get("scheme") == "exact"
            and str(e.get("network", "")).startswith("eip155:")
            and (e.get("extra") or {}).get("assetTransferMethod") in ("permit2", "eip2612"))
```

### Payload builder
Two sub-variants share one builder, switched on `extra.assetTransferMethod`:

- **EIP-2612 `permit`** — domain = the *token's* EIP-712 domain
  (`name`, `version`, `chainId`, `verifyingContract = asset`); types
  `Permit(owner, spender, value, nonce, deadline)`. Reuse the existing
  `eip712_digest` machinery with a new type dict; the signer is the `owner`.
- **Permit2** — domain = `{name: "Permit2", chainId,
  verifyingContract: 0x000000000022D473030F116dDEE9F6B43aC78BA3}` (canonical);
  types `PermitTransferFrom{ TokenPermissions(token, amount), nonce, deadline }`
  (or `PermitWitnessTransferFrom` when a witness binds the recipient).

```python
def build_valid(self, req, signer):
    method = req["extra"]["assetTransferMethod"]
    deadline = now + int(req.get("maxTimeoutSeconds", 60))
    if method == "eip2612":
        msg = {"owner": signer.address, "spender": req["payTo"],
               "value": int(req["amount"]), "nonce": _onchain_nonce_or_0(),
               "deadline": deadline}
        domain = {"name": req["extra"]["name"], "version": req["extra"]["version"],
                  "chainId": _chain_id_from_caip2(req["network"]),
                  "verifyingContract": req["asset"]}
        sig = _sign_typed(domain, _EIP2612_TYPES, msg, signer)
        return _wrap(req, signer, {"permit": msg, "signature": sig})
    # permit2: PermitTransferFrom over the canonical Permit2 domain ...
```

### Tamper map (`supports`)

| Case | Permit-style | Note |
|------|--------------|------|
| SIGNATURE | ✅ flip a sig byte | same as today |
| UNDERPAY  | ✅ `value`/`permitted.amount` < required | |
| OVERPAY   | ✅ | |
| EXPIRED   | ✅ `deadline` in the past | maps to validBefore |
| WRONG_ASSET | ✅ permit over a different token / `permitted.token` mismatch | |
| XCHAIN    | ✅ sign for another `chainId` | EIP-712 domain binds it |
| EXTREME   | ✅ `2²⁵⁶-1` amount | |
| NOT_YET   | ❌ **no `validAfter`** in a permit — only `deadline` | SKIP |
| RECIPIENT | ⚠️ **semantics differ** — see security note | |

### Security note (worth a dedicated check, not just a port)
EIP-3009 binds the recipient (`to`) **inside the signature**, so the payer
authorizes exactly that recipient. A bare **EIP-2612 permit authorizes an
allowance to a spender**; the *spender* picks the recipient at `transferFrom`
time — the signature does **not** bind `payTo`. Permit2 `PermitTransferFrom`
binds `amount`/`token`/`nonce`/`deadline` but the transfer `to` is supplied at
execution (only `PermitWitnessTransferFrom` can bind it via a witness).

So `RS-NEG-007` (redirect `to`) is not a client-side tamper here. The real
finding becomes a **facilitator/server obligation**: "does it transfer to the
advertised `payTo` and nothing else?" — which is a settlement-path check
(`RS-PAY-003` payer/recipient consistency already partly covers it) plus a new
`RS-SEC` case asserting the granted allowance/nonce can't be drained beyond the
single intended transfer. Flag this in the catalog as a *mechanism-specific*
threat, severity **critical**.

### Replay (RS-SEC-001)
EIP-2612 uses **sequential per-owner nonces**; Permit2 uses an **unordered nonce
bitmap**. Replay protection still exists but the double-settle mechanics differ —
`RS-SEC-001` (resend same payload) stays valid; building a *fresh* valid payload
needs the current on-chain nonce (EIP-2612) or any unused bit (Permit2).

### Dependencies / effort
No new runtime deps (reuses `eth-account` from `[evm]`). Effort **M**. Calibration:
extend `tools/calibration_target.py` with a permit-verifying branch, or point at a
reference server that advertises `assetTransferMethod: permit2`.

---

## 2. SVM `exact` — Solana

Fundamentally different family: `network` is `solana:<genesis-hash>`, signatures
are **Ed25519**, and the payment payload is a **base64-encoded signed Solana
transaction** (SPL-token transfer to `payTo`'s associated token account), not an
EIP-712 authorization. This needs a **new signer** and a **new builder**, but the
black-box check shapes (`RS-NEG`) map surprisingly well.

### New signer
```python
# mechanisms/svm.py — Ed25519, no EVM dep
from solders.keypair import Keypair          # or PyNaCl for raw ed25519

class SvmSigner:
    def __init__(self, kp: Keypair): self._kp = kp
    @classmethod
    def random(cls): return cls(Keypair())
    @property
    def address(self) -> str: return str(self._kp.pubkey())  # base58
```

### Gate
```python
def matches(self, e):
    return e.get("scheme") == "exact" and str(e.get("network","")).startswith("solana:")
```

### Payload builder
Per the SVM transport spec, build a transaction with an SPL `transfer`
(or `transfer_checked`) instruction: `source ATA → payTo ATA`, `amount`, `mint =
asset`, recent blockhash, fee payer per the gasless/`extra` convention; sign with
`SvmSigner`; `base64(tx.serialize())` into `PAYMENT-SIGNATURE`.

> ⚠️ Pin the exact payload envelope (field names, partial-sign vs fully-signed,
> who is fee payer) from the x402 SVM transport spec at implementation time — it
> differs from the EVM envelope and is the one part this sketch can't pre-name
> with certainty.

### Tamper map (`supports`)

| Case | SVM | How |
|------|-----|-----|
| SIGNATURE | ✅ | corrupt the tx signature bytes |
| UNDERPAY  | ✅ | transfer-instruction `amount` < required |
| OVERPAY   | ✅ | amount > required |
| RECIPIENT | ✅ | transfer to a different destination ATA — **SVM binds the recipient in the instruction**, so unlike permit this is a clean client-side tamper |
| EXPIRED   | ✅ | use a **stale/old blockhash** (Solana's tx-expiry analog of `validBefore`) |
| WRONG_ASSET | ✅ | transfer a different SPL `mint` |
| EXTREME   | ✅ | `u64::MAX` amount (note: SPL is **u64**, not u256 — overflow surface differs) |
| NOT_YET   | ❌ | no `validAfter` analog on Solana | SKIP |
| XCHAIN    | ❌ | no chainId; a Solana tx is bound to its cluster by blockhash/genesis. Optionally a *different* check: replay a devnet-signed tx against mainnet | SKIP/replace |

### Settlement & on-chain verification (RS-PAY)
- `RS-PAY-004` on-chain verification swaps `web3.eth.get_transaction_receipt`
  for an RPC `getSignatureStatuses` / `getTransaction` against a Solana RPC
  (`--rpc-url` already exists; branch on network family).
- Replay (`RS-SEC-001`): a Solana tx signature can only land once (the network
  rejects duplicates), so resubmitting the identical signed tx is the natural
  replay probe — semantically clean.

### Dependencies / effort
New optional extra `[svm]` → `solders` (or `solana-py`). Keep it lazily imported
like `eth-account` so the core stays light. Effort **M–L** (new signer + tx
construction + a Solana calibration target, which is more involved than the EVM
mock). Calibration likely against `solana-test-validator` rather than a pure mock.

---

## Rollout order

1. **Foundation (§0)** — `PaymentMechanism` refactor; existing EVM/EIP-3009 becomes
   the first mechanism; tests stay green. *Prereq for both.*
2. **Permit-style (§1)** — cheapest win: reuses the signer/dep, mostly a new typed
   struct + the recipient-binding security check. Highest ecosystem overlap (EVM).
3. **SVM (§2)** — new signer/dep/calibration; do once Solana x402 adoption
   justifies the L-sized calibration work.

Throughout: `RS-HS`/`RS-PR`/`FA`/`DI` are untouched (chain-agnostic), and every
unsupported case **SKIPs cleanly** — so adding a mechanism never regresses the
others. Each new mechanism also lands rows in `docs/conformance-catalog.md`, which
the catalog↔code drift guard (`tests/test_registry.py`) will then enforce.
