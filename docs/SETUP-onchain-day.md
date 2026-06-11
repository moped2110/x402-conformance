# Setup Checklist for On-Chain Day

Checklist for Mario so we can start directly with the settlement part (RS-PAY, FA-SET) tomorrow.
Order: 1–3 are mandatory and fast. 4 is the actual fork in the road (Anvil **or** Base Sepolia — Anvil recommended). 5 is optional.

## 1. Local Git
Git is there. In the project folder `01-x402-testsuite/`:
```bash
git init -b main
git add .
git commit -m "feat: initial implementation of x402 conformance suite v0.1.0-pre"
```
The `.gitignore` is already there and keeps `.env`, `__pycache__`, and reports out.

## 2. Python 3.11+
The project requires `>=3.11` (the cloud sandbox only had 3.10).
```bash
python3 --version        # must be 3.11 or higher
```
If older: install Python 3.11+ (python.org or package manager). This is the only hard software dependency that might be missing.

## 3. Virtual Environment (venv)
Best in a venv to keep the machine clean:
```bash
python3 -m venv .venv
source .venv/bin/activate  # Linux/macOS
# or: .venv\Scripts\activate  # Windows

pip install -e ".[dev,onchain]"
```

**Verification:**
```bash
pytest
```
If `94 passed` (or `93 passed, 1 skipped`) is shown, everything is there.

**If `pytest`/`mypy` are not found as commands** (Scripts folder not in PATH — happens with python.org installation without venv): simply call via the module, which bypasses the PATH:
```bash
python -m pytest
python -m mypy src
```

## 4. Local Chain (Anvil) — RECOMMENDED
Anvil is a local EVM chain: no faucet waiting time, no real tokens, reorgs and block time controllable (needed for RS-SEC race/replay). In the cloud sandbox, the installer was proxy-blocked — on your machine it works:
```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
anvil --version  # verification
```
That's it. We'll deploy a USDC-like test token (EIP-3009) tomorrow via `foundryup`.

## Alternative: Base Sepolia
Lower software requirements (only Python packages), but faucet-dependent and slower. If you choose this:
- a **throwaway wallet** (new private key, NEVER with real money) — we can create it tomorrow in 10 seconds, or you create it with MetaMask.
- an **RPC URL**: `https://sepolia.base.org` (public, enough to start).

> No matter which variant: **never** real money or a mainnet key comes into play. That's in the project guidelines and stays that way.

## 5. Environment (.env)
If you use Base Sepolia, you can already create a `.env` (copy of `.env.example`). Do NOT commit the key — the `.gitignore` protects you, but still be careful. For Anvil, you don't need this tomorrow at all; Anvil provides pre-funded test accounts with known keys.

## What you do NOT need to prepare
- No manual Solidity setup — `forge` (from Foundry) brings everything.
- Spec/SDK research is done; the reference target (`tools/calibration_target.py`) is standing and will grow tomorrow into a full facilitator by inserting an RPC signer.

## TL;DR — Minimal for tomorrow
1. `git init`
2. Python 3.11+
3. `pip install -e .`
4. `foundryup` (Anvil). If that fails: have Base Sepolia faucet link ready.

Once 1–4 are standing, we'll start tomorrow directly with the first real settlement.
