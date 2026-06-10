# x402 Endpoint Test- & Conformance-Suite

## Mission
Open-Source-CLI/Framework (Python), das x402-Endpoints testet: Conformance gegen die Spezifikation, Fuzzing, Reports. Später gehostetes Monitoring ("Pingdom für x402") als SaaS-Layer (19–99 €/Monat).

**Positionierung:** Das erste systematische QA-Tool für ein junges Protokoll. ISTQB-/Qualification-Testing-Denke auf x402 angewandt — wie Avionik-Qualifikationstests, nur für Payment-Handshakes.

## Kontext (Stand Juni 2026)
- x402: HTTP-402-basiertes Payment-Protokoll (Coinbase/Cloudflare; Foundation mit Google & Visa). 100+ Mio. kumulative Transaktionen auf Base.
- x402 V2 (Dez. 2025): Sessions, Multi-Chain, Service Discovery — diese Features brauchen eigene Testabdeckung.
- Volumen volatil; Infrastruktur jung, kaum Tooling. Spec kann sich ändern → Spec-Version immer explizit pinnen und vor Implementierung aktuelle Spec prüfen.
- **Kanonisches Repo: github.com/x402-foundation/x402** (coinbase/x402 ist nur noch Dev-Fork). Spec-Baseline für unseren Katalog: Commit `d454eb9` (2026-06-08). Wichtige Spec-Dateien: `specs/x402-specification-v2.md`, `specs/transports-v2/http.md`, `specs/schemes/exact/scheme_exact_evm.md`.
- HTTP-V2-Header: `PAYMENT-REQUIRED` / `PAYMENT-SIGNATURE` / `PAYMENT-RESPONSE` (base64-JSON); alte `X-*`-Header sind deprecated (V1).
- Konkurrenzlage (Juni 2026): nur agentic.market/validate (Web-Tool, Bazaar-Fokus) + upstream e2e-Tests (SDK-Interop, kein Black-Box-Testing). Lücke bestätigt.

## Scope MVP (2–3 Monate, nebenberuflich)
1. **Conformance-Checks:** 402-Handshake korrekt? Payment-Required-Header wohlgeformt? Korrekte Ablehnung bei fehlgeschlagener Settlement-Verifikation?
2. **Negativ-/Sicherheitstests:** Replay-Angriffe, manipulierte Payment-Header, Race Conditions, Timeouts.
3. **Report-Generator:** Maschinenlesbar (JSON) + menschenlesbar (Markdown/HTML), mit Pass/Fail/Severity.
4. CLI-first, CI-tauglich (GitHub Actions, Exit-Codes).

**Nicht im MVP:** Hosted Monitoring, Alerting, Dashboard — erst nach OSS-Traction.

## Architektur-Leitplanken
- Python ≥3.11, `httpx` für HTTP, `pytest` als Test-Runner-Basis, `pydantic` für Schema-Validierung, `typer` für CLI.
- Testfälle deklarativ definieren (YAML/JSON) — Conformance-Suite muss bei Spec-Updates erweiterbar sein, ohne Code anzufassen.
- Kein echter Geldfluss in Tests: Testnet (Base Sepolia) und/oder Mock-Facilitator. Niemals Mainnet-Keys im Repo oder in Configs.
- Jeder Testfall referenziert die Spec-Stelle, die er prüft (Traceability — wie bei MIL-STD-Verifikation).

## Konventionen
- Sprache im Code/Repo: Englisch (OSS, internationales Publikum). Doku für deutschen Markt separat.
- Lizenz: MIT oder Apache-2.0 (vor Launch entscheiden).
- Tests für das Tool selbst: pytest, Ziel ≥80 % Coverage der Kernlogik.
- Conventional Commits.

## Constraints
- Solo-Entwickler, Budget <5.000 € gesamt über alle Projekte, nebenberuflich.
- Linux-Entwicklungsumgebung.
- Kein Custody, kein Zahlungsdienst — reines Test-/Diagnose-Tool (regulatorisch unkritisch halten).

## Synergien
- Policy-Engine (../02-policy-engine): gemeinsame x402-Parsing-Bibliothek extrahieren, sobald Duplikation entsteht.
- Später kombinierbar zur "Agent-Payment-Trust-Suite" (mit Observability-Idee #9).

## Bei jeder Session beachten
- Aktuelle x402-Spec-Version prüfen, bevor Conformance-Regeln geschrieben/geändert werden.
- Erst Testfall-Definition (was wird geprüft, welche Spec-Referenz), dann Implementierung.
- **Testkatalog: docs/conformance-catalog.md** — Quelle der Wahrheit für alle Testfälle (IDs RS-HS/RS-PR/RS-PAY/RS-NEG/RS-SEC/FA/DI). Kalibrierung: Suite muss erst gegen die upstream-Referenzserver (`e2e/servers/`) grün laufen.
