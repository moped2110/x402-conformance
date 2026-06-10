# Known Issues & Open Problems

Stand: 2026-06-09. Bekannte Einschränkungen, Blocker und Entscheidungen, die noch offen sind. Erledigtes wandert raus, sobald es im Backlog (`../TODO.md`) oder Entscheidungs-Log (`../../ROADMAP.md`) abgeschlossen ist.

## Blocker / Einschränkungen

### I-1 · Git in der Sandbox nicht nutzbar
`git init` in der Cowork-Sandbox schlägt fehl: Das gemountete Projektverzeichnis verträgt Gits atomare Dateioperationen nicht (`config.lock` lässt sich nicht entfernen, `Operation not permitted`). Das `.git`-Verzeichnis musste manuell wieder entfernt werden.
- **Auswirkung:** Versionierung muss lokal auf Marios Rechner erfolgen (Backlog T-03).
- **Kein Codeproblem** — rein umgebungsbedingt.

### I-7 · Datei-Tool vs. Bash-Mount: Edits an bestehenden Dateien synchronisieren verzögert
In der Cowork-Sandbox synchronisieren **neu angelegte Dateien sofort** in den Bash-Mount, **In-Place-Edits an bestehenden Dateien aber verzögert/unzuverlässig**. Das führte dazu, dass pytest gegen veralteten Code lief (Checks schienen zu fehlen, obwohl sie im Quelltext standen) und bei kollidierenden Schreibvorgängen sogar eine Datei zerschnitten wurde.
- **Auswirkung:** Nur Sandbox-intern; Marios lokale Umgebung ist nicht betroffen.
- **Workaround (angewandt):** Code, der ausgeführt werden muss, nach Edits über bash vollständig neu schreiben/konvergieren; Tests mit frischem `PYTHONPYCACHEPREFIX` laufen lassen. Doku-Dateien sind unkritisch (werden nicht ausgeführt).

### I-8 · Foundry/Anvil in der Sandbox nicht installierbar
Der Foundry-Installer (`https://foundry.paradigm.xyz`) wird vom Sandbox-Proxy mit **403** blockiert; `anvil` ist nicht vorhanden. Damit ist in dieser Umgebung keine lokale EVM-Chain für echtes On-Chain-Settlement (RS-PAY) verfügbar.
- **Umgangen:** RS-NEG-Kalibrierung braucht keine Chain — sie läuft gegen `tools/calibration_target.py` (verify-fähig via SDK-Digest, ohne RPC). Vollständig grün.
- **Offen:** Echtes Settlement (RS-PAY-004) + balance-abhängige Ablehnung brauchen Anvil/Base-Sepolia auf Marios Rechner. Betrifft nur die Sandbox.

### I-2 · Python 3.10 in der Sandbox, Projekt verlangt 3.11+
Die Sandbox hat nur Python 3.10. `pyproject.toml` fordert `>=3.11`. Tests und mypy laufen in der Sandbox trotzdem grün, weil der Code keine 3.11-only-Features nutzt.
- **Auswirkung:** Keine, solange wir keine 3.11-Syntax einbauen. Marios lokale Umgebung sollte 3.11+ sein (wie im Profil festgelegt).
- **Risiko:** Niedrig. Falls wir später `tomllib` o. ä. nutzen, hier gegenprüfen.

## Offene Entscheidungen (brauchen Mario)

### I-3 · Lizenz noch nicht final
`pyproject.toml` deklariert Apache-2.0, aber es gibt keine LICENSE-Datei. → Backlog T-02. Empfehlung: Apache-2.0 (Konsistenz mit Upstream x402).

### I-4 · Testnet-Strategie: On-Chain ist beschlossen, Settlement-Tests vorbereiten
**Entscheidung (Mario, 2026-06-10):** Wir wollen On-Chain testen und bereiten jetzt dafür vor. Lizenz bleibt Apache-2.0.
Signatur-Ebene (Recovery, Domain-Bindung) ist bereits chain-frei testbar und erledigt. Für echtes Settlement (Balance, Simulation, RS-PAY-004) brauchen wir noch: Base-Sepolia-RPC + geförderten Testnet-Payer (Circle-Faucet-USDC) oder lokale Anvil-Fork. Konkrete Strategie (Nightly-Lauf vs. on-demand) noch festzulegen. Harte Linie: niemals Mainnet-Geld.

## Aus der Kalibrierung mitgenommen (keine Bugs unserer Suite)

### I-5 · Resource-Server hängen hart am Facilitator
Schon für die unbezahlte 402-Antwort initialisiert der Referenz-Server seinen Facilitator über `GET /supported`. Ist der Facilitator nicht erreichbar, liefert der Endpoint **auf allen Routen HTTP 500** statt 402.
- **Relevanz:** Verkaufsargument fürs spätere Monitoring-SaaS (T-13) — Facilitator-Ausfall = Komplettausfall, das will man überwachen.
- Für die Suite: ggf. später ein eigener Check „antwortet der Endpoint auch bei Facilitator-Problemen sauber?".

### I-6 · Upstream-Findings noch nicht gemeldet
Drei dokumentierte Findings (Spec-Lücke Facilitator-Capabilities, stilles 500-Handling, invalide Bazaar-Extensions) warten auf Einreichung — erst gegen aktuellen Upstream-`main` gegenprüfen. → Backlog T-05/T-06. Details in `calibration-2026-06-09.md`.

## Tooling-Hinweise (Sandbox-spezifisch, für Reproduzierbarkeit)

- Der x402-SDK-Facilitator-Client erbt Proxy-Umgebungsvariablen. Ohne `socksio` und ohne Entfernen der Proxy-Vars (`env -u ALL_PROXY …`) scheitert jeder Request mit `ProxyError 403`. Lokal außerhalb der Sandbox kein Thema.
