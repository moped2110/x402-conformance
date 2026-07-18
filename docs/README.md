# Documentation index

Two kinds of documents live here: **living docs** that track the current state of
the suite and are kept up to date, and a dated **`history/` archive** of
point-in-time dev-log snapshots that are *not* maintained (they record how a piece
of work stood on a given date).

## Living docs (current source of truth)

- [`architecture.md`](architecture.md) — how the suite works: the passive / active /
  settlement pipelines, the report contract, and the module map.
- [`conformance-catalog.md`](conformance-catalog.md) — the canonical check catalog.
  The implementation-status count here is pinned to the code by
  `tests/test_registry.py`, so it can't silently drift.
- [`threat-model-mapping.md`](threat-model-mapping.md) — published x402 attacks
  (arXiv) mapped to the checks that cover them, and where the suite goes beyond them.
- [`design-extended-schemes.md`](design-extended-schemes.md) — forward-looking design
  sketch for extended scheme coverage (Permit2/2612, SVM); not yet implemented.
- [`testcase-integration-analysis.md`](testcase-integration-analysis.md) — triage of an
  imported external test-case set: what became a check, what was out of scope.
- [`jp402-extension-placement-2026-06-29.md`](jp402-extension-placement-2026-06-29.md) —
  where the JP (`jp402` / `x-jp402`) metadata lives, confirmed against real fixtures.
- [`KNOWN-ISSUES.md`](KNOWN-ISSUES.md) — known limitations and environment notes.
- [`supply-chain.md`](supply-chain.md) — hashed CI dependencies, action/toolchain
  pins, vulnerability policy, and the local full release gate.
- [`support-matrix.md`](support-matrix.md) — explicit supported, passive-only,
  planned, and out-of-scope transports, schemes, networks, and mechanisms.

## `history/` — dated dev-log archive (not maintained)

Point-in-time snapshots. Superseded by the living docs above; kept for provenance.

- [`history/calibration-2026-06-09.md`](history/calibration-2026-06-09.md)
- [`history/active-checks-2026-06-10.md`](history/active-checks-2026-06-10.md)
- [`history/facilitator-checks-2026-06-10.md`](history/facilitator-checks-2026-06-10.md)
- [`history/onchain-2026-06-11.md`](history/onchain-2026-06-11.md)
- [`history/reporting-and-robustness-2026-06-12.md`](history/reporting-and-robustness-2026-06-12.md)
- [`history/SETUP-onchain-day.md`](history/SETUP-onchain-day.md) — the one-time
  on-chain-day setup checklist (on-chain settlement landed 2026-06-11).
- [`history/verify-new-features.md`](history/verify-new-features.md) — the 2026-06-12
  feature-verification runbook.
