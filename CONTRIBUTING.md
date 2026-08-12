# Contributing

Thanks for looking. This is a conformance suite: its whole value is that a verdict it
prints is one you can rely on. That makes the bar for changes here a little unusual,
and it is worth knowing where the bar sits before you spend an evening on a patch.

## What this project accepts, and what it does not

**In scope.** New checks against the x402 specification, better evidence in existing
verdicts, hardening against hostile responses, documentation that makes a verdict
easier to act on, and portability fixes.

**Out of scope, permanently.** The suite observes and verifies. It does not attack.

- No check may exploit a target beyond what the protocol requires to answer the
  question it asks.
- No code path may sign or send a transaction with mainnet value. The payment-safety
  invariant in [SECURITY.md](SECURITY.md) — chain allowlist, fail-closed, no runtime
  override — is enforced in code, not merely stated, and a patch that adds a
  configuration switch to bypass it will be declined regardless of how it is guarded.
- A failing check produces a **verdict**, not a recipe. If a report would hand its
  reader a working attack against a third party, that is a design problem with the
  check.

If you are unsure whether an idea sits on the right side of that line, open an issue
and describe it before writing code. That conversation is cheaper for both of us than
a rejected pull request.

## Setting up

Python 3.11 or newer. The repository ships a hash-pinned CI environment, which is the
one to use if you want your local run to mean the same thing as CI's:

```bash
python -m venv .venv && . .venv/bin/activate
python -m pip install --require-hashes -r requirements/ci.txt
python -m pip install --no-deps --no-build-isolation -e .
```

`pip install -e ".[dev]"` also works and is faster to iterate with, but it resolves
freely, so a green local run does not prove the locked environment is green.

## The gates

CI runs these on **every branch**, not just on pull requests — that policy exists
because handed-over work once reached `main` having never seen CI. Run them locally in
this order and you will not be surprised:

```bash
python -m ruff check src tests tools
python -m ruff format --check src tests tools
python tools/check_function_docs.py     # every function carries a docstring
python -m mypy                          # strict
python -m pytest -q --cov --cov-fail-under=85
```

Two more gates run in CI and are worth knowing about:

- **Lock reproducibility.** `requirements/ci.txt` must be exactly what
  `uv pip compile` produces from `pyproject.toml`. If you touch dependencies,
  regenerate it with the command in `.github/workflows/ci.yml` — including
  `--python-version 3.11`, which is not optional; without it the lock silently omits
  dependencies that only apply below 3.12 and installs fail on the oldest matrix entry.
- **Live regression.** `tools/verify_new_features.py` drives the suite against a
  reference target that validates with the real x402 SDK. No chain and no funds are
  involved.

If you use a shell pipeline to shorten output, set `set -o pipefail` first. `pytest -q
| tail -3` returns *tail's* exit status, which will happily report success over a red
suite.

## Adding a check

A check is not finished when it passes. It is finished when the repository still
describes itself correctly, and several tests enforce exactly that — so the fastest
path is to do all of it in one commit:

1. **Implement** it in the right module under `src/x402_conformance/checks/`, and
   register it in that module's registry. Duplicate IDs are rejected at registration.
2. **Give it metadata** that survives `test_every_check_has_valid_metadata`: a stable
   ID, a severity, and a description that tells the reader what to do about a failure.
3. **Test it** — both the failing and the passing direction. A check that cannot fail
   is decoration.
4. **Add a row to `docs/conformance-catalog.md`** with an explicit status column, and
   **update the `Implemented & tested (N checks)` count**. `test_registry.py` compares
   that number against what the code actually emits and fails on a mismatch.
5. **Update the count in `README.md`**, which is checked the same way, and add a
   `CHANGELOG.md` entry under `[Unreleased]`.

Point 4 is where most drift would come from, which is why it is a test and not a
convention.

## Commits and pull requests

- **Conventional Commits** (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`).
- **Signed commits are required** (`git commit -S`). SSH signing is fine; if you
  configure `user.signingkey`, use `$HOME` or an absolute path rather than `~`, which
  git does not expand in that setting.
- **One concern per pull request.** A refactor bundled with a behaviour change is hard
  to review and harder to revert.
- **Explain the why in the commit message.** What changed is in the diff. Why it had to
  change, and what would have gone wrong otherwise, is not — and that is the part
  someone will need in a year.
- Tests and documentation land in the same commit as the change they describe.

## Reporting a vulnerability

Do not open a public issue. See [SECURITY.md](SECURITY.md) for the private reporting
channel and for what is in and out of scope. Findings about *targets you tested with
this suite* belong to that target's own disclosure process, not here.
