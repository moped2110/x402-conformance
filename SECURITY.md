# Security Policy

`x402-conformance` is a **black-box testing tool**. It sends deliberately-invalid
payments to endpoints you point it at and never moves mainnet funds (the optional
on-chain settlement path is testnet/Anvil only). This policy covers vulnerabilities
**in the tool itself** — e.g. a way to make it emit a false PASS/FAIL, leak a signer
key, or execute attacker-controlled input from a scanned endpoint's response.

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
