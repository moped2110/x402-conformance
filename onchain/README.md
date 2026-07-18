# On-Chain Test Setup (Anvil + MockUSDC)

Local EVM chain for the settlement-level checks (RS-PAY, FA-SET, replay). All in
WSL, where Anvil and the venv live. No mainnet, ever — Anvil + a mock token only.

`MockUSDC.sol` is a faithful EIP-3009 token: it verifies the EIP-712 signature
on-chain and tracks nonces (so replay/double-settle tests work). Its on-chain
digest is byte-identical to the suite's off-chain signing (verified in Python).
The harness `/verify` path also recovers that signature, checks nonce/balance,
and executes `transferWithAuthorization` through read-only `eth_call`. This
simulates the exact settlement without broadcasting or changing token state.

The Anvil keys below are the **well-known public test keys** (deterministic
default mnemonic). They are NOT secret and hold no real value.

---

## Roles
- **Deployer / gas payer:** Anvil account #0 — deploys the token, pays gas for settle.
  - addr `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`
  - key  `0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80`
- **Payer (EIP-3009 signer):** Anvil account #1 — signs payments (gasless, needs only MockUSDC).
  - addr `0x70997970C51812dc3A010C7d01b50e0d17dc79C8`
  - key  `0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d`
- **payTo (merchant):** Anvil account #2 — `0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC`

---

## Steps (each block is one WSL terminal)

### Terminal A — start the chain (chain-id must be 84532)
```bash
anvil --chain-id 84532
# leave it running; it prints the 10 accounts + keys (should match above)
```

### Terminal B — deploy the token and fund the payer
```bash
cd onchain      # from the repo root
RPC=http://127.0.0.1:8545
DEPLOYER=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
PAYER_ADDR=0x70997970C51812dc3A010C7d01b50e0d17dc79C8

# 1) deploy MockUSDC  (if --broadcast is rejected by your forge version, drop it)
forge create src/MockUSDC.sol:MockUSDC --rpc-url $RPC --private-key $DEPLOYER --broadcast
#   -> note the "Deployed to: 0x...."  <-- this is the TOKEN address

# 2) mint 1000 test USDC (6 decimals) to the payer
TOKEN=<PASTE_DEPLOYED_ADDRESS>
cast send $TOKEN "mint(address,uint256)" $PAYER_ADDR 1000000000 \
  --rpc-url $RPC --private-key $DEPLOYER

# 3) verify the balance (expect 1000000000)
cast call $TOKEN "balanceOf(address)(uint256)" $PAYER_ADDR --rpc-url $RPC
```

When you have the **token address** and the balance reads `1000000000`, the chain
side is ready. Send me the token address — the facilitator and RS-PAY checks get
wired to it next.

## Sanity check (optional)
```bash
cast call $TOKEN "DOMAIN_SEPARATOR()(bytes32)" --rpc-url $RPC   # any 32-byte value
cast call $TOKEN "decimals()(uint8)" --rpc-url $RPC             # expect 6
```
