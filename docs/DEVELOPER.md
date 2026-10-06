# Developer guide

This is the entry point for working on x402-conformance. It is a map rather than
a manual: where a topic already has a document, this guide links to it rather
than repeating it. Where the two disagree, the linked document and the code win.

- Plain-language overview (German): [EINFACH-ERKLAERT.md](EINFACH-ERKLAERT.md)
- Documentation index: [README.md](README.md)
- Gates, scope boundary, check checklist: [../CONTRIBUTING.md](../CONTRIBUTING.md)

## What it is

x402-conformance is a black-box test client for x402 payment endpoints. It
covers three kinds of target:

- **resource servers**, with the `check` command;
- **facilitators**, with `facilitator`;
- **Bazaar discovery endpoints**, with `discovery`.

It plays an outside client and grades whether the target follows the x402 V2
specification and rejects what it must reject. Every result carries a stable
check ID, a severity and a spec reference.

**Current release: v0.7.0** (`05e72a8`).

- **81 checks** in the default catalog. The opt-in `--profile pqc` checks
  `PQC-001..006` and the `[svm]` FA-SVM group are outside that count.
- **JSON report 1.4.**
- **Spec baseline:** x402 v2 @ `d454eb9`.
- **Upstream review:** through `cb0ec5b` (2026-10-06), recorded in
  `.github/upstream-reviewed-commit`.

## Module map

[architecture.md](architecture.md) has the pipelines (passive, active,
settlement) with diagrams, and the core module table. The full package:

| Module | Role |
|---|---|
| `cli.py` | Typer CLI: `check`, `facilitator`, `discovery`, `scan`, `explain`, `diff`, `version`; consent gates and exit codes. |
| `safety.py` | Network/RPC allowlist (`eip155:1337`, `31337`, `84532`, `11155111`), no mainnet, no redirects on payment requests. |
| `runner.py`, `probe.py`, `models.py` | Passive orchestration (two unpaid requests), staged strict parsing into a `ProbeSession`, Pydantic wire models. |
| `active.py`, `payload_builder.py` | EIP-3009 requirement selection, signing, deliberate tampering for negative checks. |
| `checks/base.py` | `Check`, `CheckResult`, `Severity`, `Status`, reason codes, the passive `REGISTRY` and `register`. |
| `checks/handshake.py`, `payment_required.py`, `path_variants.py`, `timing.py` | RS-HS, RS-PR, RS-SEC-012, RS-SEC-008. |
| `checks/negative.py` | RS-NEG and RS-SEC-010 (`ACTIVE_REGISTRY`, `--active`). |
| `checks/payment.py` | RS-PAY positive settlement (`--pay`). |
| `checks/facilitator.py` | FA-SUP, FA-VER, FA-SET, FA-ERR, FA-EXT (`FA_REGISTRY`). |
| `checks/discovery.py` | DI-001..004 (`DI_REGISTRY`). |
| `checks/pqc.py`, `pqc_runner.py` | Opt-in PQC receipt profile (`PQC_REGISTRY`). |
| `checks/svm_facilitator.py`, `svm.py`, `svm_harness.py`, `svm_verify.py` | SVM foundations and the FA-SVM `/verify` group (`[svm]` extra). |
| `error_registry.py` | Generated set of upstream wire error codes (from `tools/sync_error_registry.py`). |
| `jp402.py` | Structural checks for the jp402 metadata extension. |
| `report.py`, `redaction.py`, `run_record.py` | Verdict, JSON/Markdown/SARIF/developer reports, sanitization, run records. |
| `diff.py`, `scan.py` | Report comparison and batch facilitator scans. |
| `mcp_server.py` | `x402-conformance-mcp`: the passive surface only, never signing. |

## Install from a git tag

x402-conformance is not on PyPI. Install a tag:

```bash
pip install "x402-conformance[evm] @ git+https://github.com/moped2110/x402-conformance@v0.7.0"
pip install "x402-conformance[evm,onchain] @ git+https://github.com/moped2110/x402-conformance@v0.7.0"
```

The extras `evm`, `onchain`, `svm`, `pqc` and `mcp` are explained in the
[README](../README.md#install).

## Development setup

Use Python 3.11 or newer. The hash-pinned environment is the one CI runs
([CONTRIBUTING](../CONTRIBUTING.md#setting-up)):

```bash
python -m venv .venv && . .venv/bin/activate
python -m pip install --require-hashes -r requirements/ci.txt
python -m pip install --no-deps --no-build-isolation -e .
```

`pip install -e ".[dev]"` iterates faster, but it resolves freely.

### Local chain (Anvil) for the settlement checks

The default checks and `--active` need no chain and no funds. Only `check --pay`
and `facilitator --settle` move tokens, and only on an allowlisted test network.
For a local run you need [Foundry](https://getfoundry.sh) (CI pins v1.7.1), and
the full walkthrough is [`onchain/README.md`](../onchain/README.md):

1. Run `anvil --chain-id 84532`. Chain 84532 is allowlisted, and the RPC must
   report the advertised chain ID.
2. Deploy `onchain/src/MockUSDC.sol` and mint test USDC to Anvil account #1.
3. Start `tools/onchain_facilitator.py`. It is a real facilitator plus resource
   server that settles on Anvil.
4. Run `tools/onchain_smoke.py`, or point `check --pay --rpc-url
   http://127.0.0.1:8545 --signer-key <Anvil key #1>` at it.

The Anvil keys are the public development keys and hold no value.

Without a chain, the reference target `tools/calibration_target.py` serves the
passive, active and facilitator `/verify` paths:

```bash
python tools/calibration_target.py 4500 &
x402-conformance check http://127.0.0.1:4500/data --active
x402-conformance facilitator http://127.0.0.1:4500 --resource http://127.0.0.1:4500/data
```

## Tests and gates

CI runs on every branch. Reproduce it in this order
([CONTRIBUTING](../CONTRIBUTING.md#the-gates); the full release gate including
the wheel smoke test is in [supply-chain.md](supply-chain.md#local-full-gate)):

```bash
python -m ruff check src tests tools
python -m ruff format --check src tests tools
python tools/check_function_docs.py
python -m mypy
python -m pytest -q --cov --cov-fail-under=85
python tools/verify_new_features.py
(cd onchain && forge build && forge test -vvv)
```

- The pytest suite is offline and uses mocked transports.
- `verify_new_features.py` drives the suite against the reference target in
  each bug mode.
- `requirements/ci.txt` must equal what `uv pip compile` produces, with the
  exact flags in `.github/workflows/ci.yml`.
- A scheduled job, `.github/workflows/supply-chain.yml`, audits the lock. It
  fails when the upstream review recorded in `.github/upstream-reviewed-commit`
  is more than 14 days old.

## How checks and verdicts work

**A check** is a function registered with an ID, title, `Severity` (`critical`,
`major`, `minor`) and spec reference. It returns `(Status, detail)` or
`(Status, detail, reason_code)`.

- **Statuses:**
  - `pass`;
  - `fail`;
  - `skip`, when a precondition is not met;
  - `error`, when the check itself crashed. That is a suite bug, and it makes
    the run non-conformant.
- **Reason codes** qualify a skip. A `skip` with `endpoint_absent`,
  `deferred_pending_upstream` or `settlement_pending` means "not judged", not
  "not applicable".

**The run verdict** comes from `report.assessment_exit_code()`:

| Exit | Meaning |
|---|---|
| `0` | Conformant: no failed critical/major check and no error. |
| `1` | Not conformant: a critical/major check failed, or a suite error occurred. |
| `2` | No verdict. Report 1.3+ names the reason in the top-level `inconclusiveReason`. |

The possible reasons are:

- `endpoint_absent`
- `deferred_pending_upstream`
- `settlement_pending` (new in 1.4)
- `no_checks_applicable`
- `not_x402_v2`
- `unreachable`
- `invalid_input`

A failed `minor` check is advisory and does not change the exit code.

**`settlement_pending` (since v0.7.0).** A facilitator may answer `/settle` with
`success: false`, `errorReason: "settlement_pending"` and the broadcast hash.
FA-SET-001/003 then retry once with the same payload:

- still pending: the check is skipped with reason `settlement_pending`, and the
  run gets exit 2;
- a different hash: that is a re-broadcast, and FA-SET-003 fails;
- the same hash, reconciled: the check passes.

FA-SET-004 requires the pending answer to name its transaction.

**Reports.**

- JSON is validated against [`report.schema.json`](../report.schema.json)
  (`reportVersion` 1.4). Major 1 is the stable consumer contract.
- Markdown, SARIF, the developer `--fix` report, scans and run records share the
  same verdict.
- Targets are persisted as origin plus fingerprint.

## Adding a check

Follow the checklist in [CONTRIBUTING](../CONTRIBUTING.md#adding-a-check). In
short, all in one commit:

1. Implement and register the check in the right `checks/` module. Duplicate IDs
   fail at import.
2. Give it valid metadata (ID, severity, a description that says how to fix a
   failure).
3. Test it in both directions.
4. Add a row to [conformance-catalog.md](conformance-catalog.md) and update the
   `Implemented & tested (N checks)` count and the implementation-status list.
   `tests/test_registry.py` and `tests/test_catalog_status.py` compare both with
   the code.
5. Update the count in the README, and add a `CHANGELOG.md` entry under
   `[Unreleased]`.

A new run-level reason or report field is a report-schema change: bump the
minor `reportVersion` and update `report.schema.json`. Consumers such as the
hosted lab read major 1 and pass unknown reasons through.

**After an upstream review:**

- regenerate the error registry with
  `python tools/sync_error_registry.py --upstream /path/to/x402`;
- record the review in `docs/upstream-review-YYYY-MM.md` and
  [support-matrix.md](support-matrix.md);
- move `.github/upstream-reviewed-commit`.

## Release process

The pattern of v0.5.0 to v0.7.0:

1. **Feature PRs.**
   - Use Conventional Commit subjects (`feat:`, `fix:`, `docs:`, ...), and put
     the change in `CHANGELOG.md` under `## [Unreleased]`.
   - CONTRIBUTING asks for signed commits.
2. **Release PR** with one commit `release: X.Y.Z`:
   - bump `version` in `pyproject.toml`;
   - turn `[Unreleased]` into `## [X.Y.Z] — YYYY-MM-DD`;
   - update the README status section;
   - update the catalog's `Implementation status (vX.Y.Z)` heading, which
     `tests/test_catalog_status.py` checks against the package version.
3. **Merge method: squash** (`gh pr merge --squash`). The PR title becomes the
   commit subject on `main`, with `(#N)` appended. Do this only after CI is
   green, then delete the branch. Never force-push `main`.
4. **Annotated tag** `vX.Y.Z` on the squashed release commit:
   - message `x402-conformance X.Y.Z`, plus a summary paragraph;
   - pushed with `git push origin vX.Y.Z`.

   Since v0.3.0 the tags have no GitHub release object. There is no `v0.4.0`
   tag; do not create one retroactively.
5. **Consumers bump their pins in their own PRs.** The website backend pins
   this package by tag, and its pin-consistency test requires the settings,
   `pyproject.toml` and `uv.lock` to agree.

## How the repositories relate

| Repository | Visibility | Current release | Role |
|---|---|---|---|
| **x402-conformance** | public | **v0.7.0** (`05e72a8`) | Black-box x402 protocol client: 81 checks, JSON report 1.4. |
| psv | public | v0.5.0 (`21cee3b`) | System verification against independent chain truth; reconciliation report 2.0, run record 1.1. |
| rvf | private | v0.2.0 (`c1144b6`) | Refund and escrow correctness verifier. |
| X402testwebside (x402 Test Lab) | private | no release tags | Hosted service that runs both engines. |

- **x402-conformance and psv share no code.** They agree on formats where they
  meet: the PQC profile verifies psv's receipt-v2 format against a shared
  canonicalization vector. psv checks what a payment system *believes* against
  the chain. This suite checks what an endpoint *says* on the wire.
- **The website** pins this package (`[onchain]` extra) and psv by tag.
  - For each run it starts the `x402-conformance` CLI as a sandboxed subprocess
    and reads the versioned JSON report.
  - Its check catalog and derived report formats use this package's public
    Python APIs.
  - Its frontend catalog mirror is generated from the pinned version.
- **rvf** pins psv through an optional extra. Its import guard
  (`tests/test_no_originate_guard.py`) keeps psv's signing and broadcast modules
  out. **rvf does not depend on x402-conformance**; the two share conventions,
  not code. The auth-capture lifecycle that this suite deliberately does not
  grade (see [support-matrix.md](support-matrix.md)) is proposed as an rvf
  verifier.
- **Dependencies point one way.** This package never imports psv, rvf or the
  website.
