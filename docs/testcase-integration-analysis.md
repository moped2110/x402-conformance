# Integration der x402-Testcases.md — Analyse & Einordnung

**Quelle:** `x402-Testcases.md` (Stand 2026-06-10), ~120 Testfälle in 6 Teilen.
**Frage:** Wie binden wir diese in x402-conformance ein?
**Kurzantwort:** Nur ein Teil davon gehört in dieses Tool. Der größere Teil testet etwas anderes — und das ist gut so.

---

## Die zentrale Unterscheidung (bitte ernst nehmen)

`x402-Testcases.md` ist ein Testkatalog für **den Bau und Betrieb eines x402-Zahlungssystems** — also für einen Server/Agenten, der Zahlungen entgegennimmt, On-Chain settled, RPC-Nodes befragt, eine DB pflegt, Reconciliation fährt.

**x402-conformance ist etwas anderes:** ein **Black-Box-Tester**, der von außen auf einen x402-Endpoint zeigt und prüft, ob dessen *Protokollverhalten* der x402-V2-Spec entspricht. Wir sind ein externer Client, kein Zahlungs-Backend. Wir haben keine RPC-Quoren, keine DB, keine Reconciliation — und sollen die auch nicht haben.

**Konsequenz, direkt gesagt:** Etwa 60–70 % des Dokuments ist mit einem Black-Box-Tester *prinzipiell nicht prüfbar*, weil es internen Zustand des Systems betrifft (DB-Locks, RPC-Failover, Memory-Leaks, ABI-Drift). Das in x402-conformance hineinzuziehen würde das Produkt verwässern und aus einem scharfen, in einem Wochenende erklärbaren Tool ein Mehrjahres-Plattformprojekt machen. Genau das will die Portfolio-Strategie *nicht* (Schaufelverkäufer, kein Plattformbau).

Der disziplinierte Weg: die ~20–30 % Black-Box-prüfbaren Fälle ernten (einige davon sind echte Lücken, die wir noch nicht hatten), den Rest **bewusst an die richtigen Portfolio-Projekte weiterreichen**, damit die Einsicht nicht verloren geht.

---

## Kategorie 1 — IN SCOPE: gehört in x402-conformance

### 1a) Bestätigt bereits abgedeckt (Validierung unseres Katalogs)
Diese Upload-Fälle entsprechen vorhandenen Katalog-IDs — schöne Bestätigung, dass `conformance-catalog.md` solide ist:

| Upload | Unser Katalog | Thema |
|--------|---------------|-------|
| Test 8 Unterzahlung | RS-NEG-005 | value < amount |
| Test 9 Überzahlung | RS-NEG-006 | exact: muss exakt sein |
| Test 19 Replay-Angriff | RS-SEC-001 | Replay nach Settlement |
| Test 20 MITM Adress-Tausch | RS-NEG-007 | Recipient-Mismatch (EIP-712 verteidigt) |
| Test 13/14 Doppel-/Concurrent-Pay | RS-SEC-001/-002 | Idempotenz, Race |
| N16 Amount manipuliert | RS-NEG-013 | Server validiert gegen eigene Preisdaten |
| N17 Resource-ID gespooft | RS-SEC-003 | Cross-Resource-Replay |
| N15 Expiry clientseitig manipuliert | RS-NEG-008 | Server erzwingt eigenes Timeout |
| N11/N12 Block-Replay/Nonce-Reuse | RS-SEC-004 | (Signatur-Ebene; Settlement-Teil out) |

### 1b) Genuin NEU — als Checks ergänzen (die Gewinne aus dem Upload)
Diese sechs sind Black-Box-prüfbar und hatten wir noch nicht. Sie wandern in `conformance-catalog.md`:

| Neue ID | Quelle | Check | Typ |
|---------|--------|-------|-----|
| **RS-HS-007** | PR1 | 402 mit Zahlungsdetails darf nicht cachebar sein → `Cache-Control: no-store`/`private` prüfen, kein `public`/langes `max-age` | passiv |
| **RS-PR-013** | N1/N2 | `payTo`/`asset` müssen zum CAIP-2-Namespace des `network` passen (keine Solana-Adresse auf `eip155`) | passiv |
| **RS-PR-014** | N5 | `amount` muss > 0 sein (nicht "0", nicht negativ) | passiv |
| **RS-NEG-014** | N10 | Zahlung mit gültig-formatiertem, aber **falschem Asset-Contract** → muss abgelehnt werden (Server prüft Contract-Adresse, nicht Symbol) | aktiv |
| **RS-SEC-010** | C0 (Fables Einwand) | **Cross-Chain-Signature-Replay**: gültig signierte Payload für Netz A gegen Endpoint B mit anderer `chainId` → muss abgelehnt werden (EIP-712-Domain bindet chainId) | aktiv |
| **RS-SEC-011** | N4/N13 | Extrem große `amount`/Beträge (nahe 2²⁵⁶) → Tooling parst ohne Overflow, Endpoint antwortet sauber | robustness |

**Fables Einwand zu C0 ist berechtigt** und gut erkannt: Der gefährliche Replay bei x402 ist nicht der klassische Netzwerk-Replay, sondern der On-Chain-Signature-Replay über Chains hinweg. Die Verteidigung (EIP-712-Domain-Separator mit chainId) ist genau das, was RS-SEC-010 prüft. Übernommen.

---

## Kategorie 2 — ROUTE ELSEWHERE: gehört zu anderen Portfolio-Projekten

Wertvoll, aber nicht für einen Black-Box-Conformance-Tester. Diese Notizen wandern in die jeweiligen Projekt-Backlogs, damit die Arbeit nicht verloren geht:

### → #09 Agent-Spend-Observability ("Datadog für Agent-Payments")
Reconciliation (O1–O4, D3 — DB-vs-Chain-Drift), Stuck-Payment-Detection (O2), RPC-Quorum/Health (N20–N23, C10), Provider-Inkonsistenz (D5), Audit-Log-Integrität (O3), verwaiste Settlements (O4). **Das ist exakt das Observability-Produkt** — Sichtbarkeit über Zahlungen, nicht Conformance eines Endpoints.

### → #10 x402-Paywall-Gateway mit DE-Rechnungsstellung
Currency-Mismatch/Slippage (PR5, T10), Refund-Pfad (R6, G7), Multi-Recipient-Split (PR6), Belegerstellung (R4 — Schnittmenge mit #03), Gebühren-Handling. **Das Gateway-Produkt**, das EUR-Belege und USt abwickelt.

### → #02 Spend-Policy-Engine (Guardrails)
Agent-Budget-Loop (N24 — LLM in Schleife), Spend-Limit (Test 6), kompromittierter Key/anomales Pattern (N25), Agent lehnt ab (Test 5, N26/N27). **Das ist wörtlich die Domäne der Policy-Engine** — deterministische Limits außerhalb des LLM.

### → #03 DAC8-Tool
R4 (DAC8-konformer Beleg pro Settlement), R1 (Travel-Rule-Schwelle, IVMS101).

### → Compliance allgemein (Kategorie R)
Sanktions-Screening (R2), MiCA-Stablecoin-Status (R3), Geo-Fencing (R5) — relevant für #09/#10 beim Launch, anwaltlich zu prüfen. Nicht Conformance.

---

## Kategorie 3 — OUT OF SCOPE: andere Werkzeugkategorie

Gehört in kein einzelnes Conformance-Tool:

- **Teil 6 Last-/Stresstests (ST1–ST11, S1–S6):** k6/Artillery + Anvil. Performance-Testing ist eine eigene Disziplin. Höchstens *sehr* spätes, separates Modul — explizit nicht der Conformance-Kern.
- **Client-/Wallet-UX (U1–U7):** Browser-Extension-Konflikte, Wallet-Popup-Timeouts, App-Resume. Verhalten des Clients, nicht des Endpoints.
- **Supply-Chain/Deploy (SC1–SC6):** ABI-Drift, Library-Bumps, Blue/Green, Config-Drift. Das ist die CI/CD-Sorge des *Implementierers* — eine berechtigte, aber interne Disziplin. (SC1 ABI-Drift ist Fables Top-1-Risiko — zu Recht, aber von außen nicht prüfbar; ein Monitoring-Signal in #09 kann es indirekt fangen.)
- **Token-Quirk-Internals (T1 USDT-void-return, T3 Internal-Tx, T5 Fee-on-Transfer, T6 Rebase, T8 Permit2-Parsing, T9 Multicall):** Das betrifft, *wie ein Settlement-Backend Zahlungen erkennt* — Server-intern. Black-Box sehen wir nur das advertised `asset` (deckt RS-PR ab).
- **Chain-Settlement-Tiefe (C1 Soft/Hard-Finality, C4–C6 Confirmations, C9 Sequencer, Test 7/11/12 Reorg/RBF):** braucht Zugriff auf die Settlement-Logik des Servers. Out für Black-Box.

---

## Konkreter Integrationsplan

1. **Sofort (dieser Stand):** Sechs neue Checks (1b) in `conformance-catalog.md` ergänzen. RS-NEG-014 und RS-SEC-010 werden im Zuge von T-01 (Payload-Builder vorhanden) implementiert; die passiven RS-HS-007/RS-PR-013/-014 sind sofort umsetzbar.
2. **Backlog-Verweise:** In den CLAUDE.md von #02/#09/#10/#03 je eine Zeile „Testideen aus testcase-integration-analysis.md Kategorie 2 prüfen" — sobald diese Projekte starten.
3. **Bewusst NICHT tun:** Last-/Stress-, UX-, Supply-Chain-, Settlement-Internals in x402-conformance ziehen. Wenn überhaupt, später als getrennte Tools.

## Was Mario entscheiden sollte
- Sind RS-HS-007/RS-PR-013/-014 (drei schnelle passive Checks) okay zur sofortigen Aufnahme? (Empfehlung: ja, kleiner Aufwand, echter Mehrwert.)
- Soll ich die Backlog-Verweise in #02/#09/#10 schon jetzt setzen, obwohl die Projekte noch nicht laufen? (Empfehlung: ja, eine Zeile pro Projekt, kostet nichts und sichert die Idee.)
