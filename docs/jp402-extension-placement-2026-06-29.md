# x-jp402 placement — confirmed against real fixtures (2026-06-29)

Resolves the provisional note in `RS-PR-015` / `jp402.find_jp402`
(*"Live-402 placement of x-jp402 is provisional — confirm against a real fixture;
the separate jp402.tax breakdown is not covered yet"*), using the real wire shapes
from a production JPYC deployment (facilitator `https://yen402.com`, the
`x402-jpyc` reference resource server). Golden fixtures live in
`tests/fixtures/jp402/`.

## Two distinct surfaces — the JP metadata is split

| | Live 402 envelope (what `check` sees) | OpenAPI discovery doc (what a registry/catalog sees) |
|---|---|---|
| Key | **`jp402`** (no `x-` prefix) | **`x-jp402`** (with `x-` prefix) |
| Location | on each `accepts[]` entry | at `info` level (currency) + per-operation (invoice) |
| Payload | **`tax`** breakdown `{ excl_jpyc, vat_jpyc, rate }` | **`invoice`** `{ qualifiedIssuer, registrationNumber, smallAmountException }` |
| Carries `registrationNumber`? | **No** | **Yes** (`^T[0-9]{13}$`) |

The qualified-invoice metadata (`registrationNumber`) that `RS-PR-015` /
`validate_invoice` checks **does not appear on the live 402** — it lives in the
OpenAPI discovery doc. The live 402 instead carries a per-quote **tax breakdown**.

## Implications for the checks

1. **`find_jp402` currently looks for `x-jp402`** in `extensions` / `accepts[]`.
   A real live 402 puts the block under **`jp402`** on `accepts[]`, so the lookup
   would miss it as-is. Two clean options: match both keys, or scope the
   invoice check to the discovery layer (where `x-jp402.invoice` actually lives).
2. **The black-box `check` path** (live 402) is the natural home for a
   **`jp402.tax`** structural check — the field a live 402 actually exposes:
   `excl_jpyc` / `vat_jpyc` / `rate`, with the integrity relation
   `amount == (excl_jpyc + vat_jpyc) · 10^k` for some power of ten `k`. This is
   scale-invariant on purpose: the observed deployment carries whole-JPYC tax
   fields (`10` + `1`) against an 18-dp atomic `amount` (`11e18`), so they differ
   by the token's decimals; `k == 0` is the special case where the breakdown is
   itself in atomic units. (An earlier draft of this note said
   `excl + vat == amount` in atomic units, which only holds in that `k == 0`
   case — RS-PR-015 implements the scale-invariant relation, validated against
   the golden fixtures.) The invoice/registrationNumber check fits better when
   validating a published OpenAPI doc.
3. This deployment is still **x402Version 1**; placement of `jp402` on `accepts[]`
   is unaffected by the v1→v2 envelope differences.

Schema reference (community extension, not core):
`https://raw.githubusercontent.com/kakedashi3/jp402-registry/main/schema/x-jp402.schema.json`
