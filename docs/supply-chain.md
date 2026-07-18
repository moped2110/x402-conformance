# Build and supply-chain policy

The package keeps compatible version ranges in `pyproject.toml`, while CI and
release verification use the exact, hashed dependency graph in
`requirements/ci.txt`. The lock is universal across the supported Python
versions and includes the `dev`, `calibration`, `release`, and `supply-chain`
extras. Installing it with `--require-hashes` makes an unreviewed distribution
file or dependency version a hard failure.

## Local full gate

Use Python 3.11 or newer and Foundry **v1.7.1**. From the repository root, extend
the active virtual environment and run the same gates as CI:

```bash
python -m pip install --require-hashes -r requirements/ci.txt
python -m pip install --no-deps --no-build-isolation -e .
python -m pip check

python -m ruff check src tests tools
python -m ruff format --check src tests tools
python -m mypy
python -m pytest -q --cov --cov-fail-under=85
python tools/verify_new_features.py

python -m build --no-isolation
python -m twine check dist/*
python -m venv .venv-wheel-smoke
.venv-wheel-smoke/bin/python -m pip install --require-hashes -r requirements/ci.txt
.venv-wheel-smoke/bin/python -m pip install --no-deps dist/*.whl
.venv-wheel-smoke/bin/python -m pip check
.venv-wheel-smoke/bin/x402-conformance version
.venv-wheel-smoke/bin/x402-conformance explain RS-HS-001

foundryup -i v1.7.1
pushd onchain
forge build
forge test -vvv
popd
```

The wheel smoke environment is deliberately separate from the development
environment. `build --no-isolation` is deliberate too: the build backend comes
from the hashed lock instead of being downloaded into an implicit, unpinned
PEP 517 environment.

## Updating dependencies

Regenerate the lock only after reviewing direct and transitive release notes:

```bash
uv pip compile pyproject.toml \
  --extra dev --extra calibration --extra release --extra supply-chain \
  --universal --generate-hashes --no-annotate --upgrade \
  -o requirements/ci.txt
```

Then run the full gate above and review the lock diff, including package names,
versions, environment markers, and hashes. Do not hand-edit hashes. Runtime
dependency ranges should remain broad enough for a library consumer; exact
versions belong in the CI lock unless compatibility or a security boundary
requires a metadata cap.

## Automated policy

- All third-party Actions are pinned to reviewed commit SHAs. Version comments
  are informational; updating the comment without the SHA changes nothing.
- Workflows have explicit `contents: read` permissions. No CI job receives
  package-write or OIDC-token permissions.
- The regular CI lock job recompiles against the existing selections and fails
  if project metadata and the checked-in lock diverge.
- The weekly `Supply chain` workflow audits the hashed graph with `pip-audit`
  and performs an upgrade resolution. A vulnerability or available lock update
  fails the job and requires a reviewed dependency pull request.
- Vulnerability exceptions are not silently embedded in the workflow. If an
  advisory is not exploitable, document the package, advisory ID, reasoning,
  owner, and expiry date in `SECURITY.md` before adding a temporary
  `--ignore-vuln` entry. Remove the exception by its expiry date.
- The Solidity harness uses Foundry v1.7.1 and Solidity 0.8.28. It has no remote
  Solidity library dependency, so `forge build` and `forge test` do not fetch a
  mutable `lib/` tree.

Release artifacts are considered valid only when both the Python distribution
gate and the Foundry harness gate pass.
