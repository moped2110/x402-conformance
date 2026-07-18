# Security Policy

`x402-conformance` is a **black-box testing tool**. It sends deliberately-invalid
payments to endpoints you point it at and never moves mainnet funds (the optional
on-chain settlement path is testnet/Anvil only). This policy covers vulnerabilities
**in the tool itself** — e.g. a way to make it emit a false PASS/FAIL, leak a signer
key, or execute attacker-controlled input from a scanned endpoint's response.

## Payment safety invariant

Payment-bearing modes enforce a built-in testnet/local CAIP-2 allowlist. Mainnets
and unknown networks fail closed with no override. `--pay` and `facilitator
--settle` additionally require a funded testnet signer plus an RPC whose
`eth_chainId` matches the advertised network. Signed payment requests, facilitator
`/verify` and `/settle` bodies, and RPC requests do not follow redirects, so payment
material cannot be forwarded to another origin or through an HTTPS downgrade.

The CLI rechecks the network before signer creation, and the underlying library
runner checks again before building a payload. Transactional modes cannot be
enabled by an auto-discovered TOML config; they require an explicit flag per run.

## Reporting a vulnerability

Please report privately — do **not** open a public issue for a security bug.

- Preferred: open a **GitHub private security advisory** on this repository
  (repo → *Security* → *Report a vulnerability*).
- The advisory is private to the maintainer until a fix is released.

Include: affected version, a minimal reproduction, and the impact you observed.

## What to expect

- Acknowledgement within a few days.
- A fix or mitigation plan, and coordinated disclosure once a fix is available.
- Credit in the release notes if you would like it.

## Scope notes

- **In scope:** false conformance verdicts, signer-key or `--signer-key` leakage,
  code execution / injection from a scanned endpoint's response, ReDoS or crashes on
  hostile input, dependency vulnerabilities in the shipped package.
- **Out of scope:** vulnerabilities in the *endpoints you test* — those belong to the
  endpoint's own disclosure process. Findings this tool surfaces about a third-party
  facilitator should be reported to that project under its own policy.

## Supported versions

The latest released version on the default branch is supported. This is a
pre-1.0 tool; fixes land on `main`.
