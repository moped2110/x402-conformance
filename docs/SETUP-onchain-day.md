# Vorbereitung On-Chain-Tag

Checkliste für Mario, damit wir morgen direkt mit dem Settlement-Teil (RS-PAY,
FA-SET, balance-abhängige Ablehnung) loslegen können statt Werkzeug zu installieren.

Reihenfolge: 1–3 sind Pflicht und schnell. 4 ist die eigentliche Weggabelung
(Anvil **oder** Base Sepolia — Anvil empfohlen). 5 ist optional.

---

## 1. Git-Repo initialisieren (2 Min)
Git ist da. Im Projektordner `01-x402-testsuite/`:

```bash
cd 01-x402-testsuite
git init -b main
git add -A
git commit -m "feat: x402-conformance suite (RS-HS/RS-PR/RS-NEG/FA/DI, 85 tests)"
```

Die `.gitignore` ist schon da und hält `.env`, `__pycache__`, Reports draußen.

## 2. Python 3.11+ prüfen (1 Min)
Das Projekt verlangt `>=3.11` (die Cloud-Sandbox hatte nur 3.10).

```bash
python3 --version        # muss 3.11 oder höher sein
```

Falls älter: Python 3.11+ installieren (python.org oder Paketmanager). Das ist
die einzige harte Software-Abhängigkeit, die fehlen könnte.

## 3. Projekt + Abhängigkeiten installieren (2 Min)
Am besten in einem venv, damit der Rechner sauber bleibt:

```bash
cd 01-x402-testsuite
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"            # zieht httpx, pydantic, typer, eth-account, pytest, mypy
pytest -q                          # erwartet: 85 passed
mypy                               # erwartet: Success
```

Wenn `85 passed` steht, ist alles Nötige für die bestehende Suite da.

---

## 4. Test-Chain wählen — **Anvil empfohlen**

### Variante A: Anvil / Foundry (empfohlen, lokal, deterministisch)
Anvil ist eine lokale EVM-Chain: keine Faucet-Wartezeit, keine echten Tokens,
Reorgs und Block-Zeit steuerbar (brauchen wir für RS-SEC-Race/Replay). In der
Cloud-Sandbox war der Installer proxy-blockiert — auf deinem Rechner geht er:

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup                          # installiert anvil, cast, forge
anvil --version                    # Verifikation
```

Das war's. Wir deployen morgen einen USDC-artigen Test-Token (EIP-3009) per
`forge`/`cast` direkt in Anvil — dafür musst du nichts vorbereiten.

### Variante B: Base Sepolia (echtes Testnet, falls Anvil zickt)
Software-ärmer (nur Python-Pakete), aber Faucet-abhängig und langsamer. Falls du
diesen Weg willst, brauchst du:
- eine **Wegwerf-Wallet** (neuer Private Key, NIE mit echtem Geld) — können wir
  morgen in 10 Sekunden erzeugen, oder du legst sie mit MetaMask an.
- **Test-USDC** auf Base Sepolia vom Circle-Faucet:
  https://faucet.circle.com (Network: Base Sepolia).
- eine **RPC-URL**: `https://sepolia.base.org` (öffentlich, reicht zum Start).

> Egal welche Variante: Es kommt **niemals** echtes Geld oder ein Mainnet-Key
> ins Spiel. Das steht so in der Projekt-Leitlinie und bleibt so.

---

## 5. Optional: `.env` vorbereiten
Wenn du Base Sepolia nutzt, kannst du schon eine `.env` anlegen (Kopie von
`.env.example`). Den Key NICHT committen — die `.gitignore` schützt dich, aber
trotzdem aufpassen. Bei Anvil brauchst du das morgen gar nicht; Anvil liefert
vorfinanzierte Test-Accounts mit bekannten Keys mit.

---

## Was du NICHT vorbereiten musst
- Kein Node/npm — wir testen Python-seitig.
- Kein Solidity-Setup von Hand — `forge` (aus Foundry) bringt alles mit.
- Keine Datenbank, kein Docker.
- Die Spec/SDK-Recherche ist erledigt; das Referenzziel (`tools/calibration_target.py`)
  steht und wächst morgen durch Einsetzen eines RPC-Signers zum vollen Facilitator.

## TL;DR — Minimal für morgen
1. `git init` + erster Commit.
2. Python 3.11+ vorhanden?
3. `pip install -e ".[dev]"`, `pytest -q` → 85 passed.
4. `foundryup` (Anvil). Falls das scheitert: Base-Sepolia-Faucet-Link bereithalten.

Wenn 1–4 stehen, starten wir morgen direkt mit dem ersten echten Settlement.
