# Technical review handoff

This guide is the shortest reliable route through an independent review of
`x402-conformance` 0.2.0. It describes the shipped code, not the aspirational
catalog. The authoritative protocol baseline is `x402-foundation/x402@d454eb9`;
the latest upstream comparison and every support claim are recorded in
[`support-matrix.md`](support-matrix.md).

## Mission and non-goals

The package is a protocol-level, black-box conformance and robustness suite for
x402 resource servers, facilitators, and Bazaar discovery endpoints. It produces
stable, specification-traceable findings that another system can consume.

It is not a wallet, custodian, payment service, certification authority, broad
vulnerability scanner, tax/legal assessment, or mainnet settlement client. A
clean result applies only to rows marked **supported** in the support matrix.
Passive-only, planned, and out-of-scope mechanisms are deliberately excluded
from the verdict.

## Safety boundary to review first

- Mainnet and unknown payment networks fail closed before payload construction;
  there is no runtime override.
- Signing is restricted to local chains 1337/31337, Base Sepolia 84532, and
  Ethereum Sepolia 11155111. SVM foundations allow only devnet/testnet and do
  not expose a runnable settlement group.
- Positive resource or facilitator settlement requires an explicitly supplied,
  funded testnet key and an RPC whose `eth_chainId` exactly matches the
  advertised CAIP-2 network.
- Payment-bearing resource, `/verify`, `/settle`, and RPC requests never follow
  redirects. Payment material must not cross an origin or HTTPS downgrade.
- Auto-discovered TOML configuration cannot enable `active`, `pay`, or `timing`;
  each sensitive mode requires explicit operator intent.
- Active batch `/verify` probes require an authorization acknowledgement.
  Discovery cross-fetches treat catalog URLs as hostile input and enforce DNS
  pinning, public-address checks, redirect revalidation, size/request caps, and
  an explicit exact-host/IP/CIDR allowlist.
- Reports and run records omit keys, sanitize URL-bearing endpoint text, reduce
  targets to origins, and retain a stable full-target fingerprint.

The central policy is `SafetyPolicy` in `safety.py`. Review every caller as well
as the policy itself; library callers must receive the same protection as CLI
callers.

## Pinned support and check inventory

The canonical status inventory is
[`conformance-catalog.md`](conformance-catalog.md). The shipped catalog contains
63 implemented checks:

| Group | Invocation | Coverage |
|---|---|---|
| `RS-HS-001..007` | `check` | HTTP 402 handshake and caching |
| `RS-PR-001..016` | `check` | strict PaymentRequired content, identity, JP metadata |
| `RS-NEG-*`, `RS-SEC-*` | `check --active` | signed semantic negatives, robustness, leak protection |
| `RS-PAY-001..004`, `RS-SEC-001/002` | `check --pay` | positive settlement, exact Transfer proof, replay/race |
| `FA-SUP-*`, `FA-VER-*`, `FA-ERR-001` | `facilitator` | supported and verify behavior |
| `FA-SET-001..003` | `facilitator --settle` | testnet settle, invalid settle, double settle |
| `DI-001..003` | `discovery` | strict Bazaar schema, filters, safe live cross-check |

`RS-SEC-009` is enforced on every active rejection path rather than as a
standalone registry function. Planned but unshipped rows are `RS-NEG-010`,
`FA-VER-001`, and `FA-VER-005`. Permit2, ERC-7710, runnable SVM, `upto`, and
batch settlement are also explicitly non-shipped. Unknown names never imply
coverage.

## Architecture and data flow

```text
operator / CI
  -> Typer CLI and typed config validation
  -> passive resource | active negative | positive pay | facilitator | discovery
  -> strict wire parsing and stable check registries
  -> CheckResult(check_id, severity, spec_ref, status, detail)
  -> one shared 0/1/2 assessment
  -> JSON / Markdown / SARIF / developer report / run record
```

Passive resource flow:

```text
HTTP response -> build_probe -> base64 -> JSON object -> strict Pydantic model
              -> ProbeSession -> RS-HS/RS-PR registry -> ordered results
```

Active and positive flow:

```text
unpaid challenge -> safe exact/EIP-3009 selection -> network preflight
  -> EIP-712 payload construction -> no-redirect request
  -> strict rejection or SettlementResponse classification
  -> optional exact receipt/Transfer proof -> replay/race evidence
```

The endpoint, RPC, discovery documents, redirect destinations, report text, and
persisted files are separate trust boundaries. Endpoint data never becomes a
Python exception-based PASS. Transport failures, malformed success evidence,
ambiguous Transfer events, and suite exceptions remain failure or inconclusive
signals. The run-record checksum detects accidental modification; it is not a
signature or adversarial trust anchor.

## Primary modules and APIs

| File | Responsibility and review entry points |
|---|---|
| `cli.py` | Commands `check`, `facilitator`, `discovery`, `scan`, `explain`, `diff`, and `version`; typed config and exit handling. |
| `runner.py`, `probe.py`, `models.py` | Passive requests, staged hostile-input parsing, strict wire contracts. |
| `active.py`, `payload_builder.py` | preflight, EIP-3009 signing, semantic tampering, bounded retries, no-redirect senders. |
| `checks/base.py` | stable registry, duplicate-ID guard, severity/status/result contracts. |
| `checks/handshake.py`, `checks/payment_required.py` | passive resource verdicts. |
| `checks/negative.py`, `checks/timing.py` | active rejection and advisory timing verdicts. |
| `checks/payment.py` | positive settlement, exact receipt/log proof, replay and race. |
| `checks/facilitator.py` | strict `/supported`, `/verify`, and opt-in `/settle`. |
| `checks/discovery.py` | schema/filter checks and SSRF-resistant cross-fetching. |
| `safety.py` | immutable network allowlists and exact RPC-chain validation. |
| `report.py`, `redaction.py`, `run_record.py` | shared assessment, output formats, sanitization, integrity-checked records. |
| `diff.py`, `scan.py` | strict report comparison and redacted batch aggregation. |
| `svm.py`, `jp402.py` | non-runnable SVM building blocks and optional JP structural checks. |
| `tools/calibration_target.py` | independent SDK-backed calibration target and injected bug modes. |
| `tools/onchain_facilitator.py`, `tools/onchain_smoke.py` | local-chain settlement oracle and end-to-end proof. |
| `tools/check_function_docs.py` | AST gate for every sync/async function, method, and nested function in `src/` and executable `tools/`. |

## Report and run-record contracts

- JSON reports use `reportVersion: "1.3"` and are validated by the repository
  root `report.schema.json`. Consumers should pin the major version.
- Every result carries `check_id`, `title`, `severity`, `spec_ref`, `status`, and
  sanitized `detail`, plus an optional `reason_code` (`deferred_pending_upstream`
  or `endpoint_absent`) qualifying a SKIP. Result ordering is deterministic.
- An exit-2 report carries a top-level `inconclusiveReason` naming why the verdict
  is inconclusive (`endpoint_absent` / `deferred_pending_upstream` / `not_x402_v2` /
  `no_checks_applicable` / `unreachable` / `invalid_input`); it is null otherwise.
- Exit `0` means sufficient supported evidence and no gating failure; exit `1`
  means a critical/major failure or suite ERROR; exit `2` means inconclusive,
  unreachable, invalid input, empty/all-SKIP, or a non-V2 assessment.
- Markdown, SARIF 2.1.0, developer output, JSON, scans, and records use that same
  assessment. Minor failures remain advisory.
- Run records use `schemaVersion: "1.0"`, store the tool/spec/environment,
  sanitized inputs, full results and verdict, and derive `runId` from canonical
  JSON excluding `runId`. `runs.jsonl` is an append-only operational index, not
  an authenticated audit log.

## CI and local verification matrix

CI installs the exact hashed `requirements/ci.txt` graph, installs the project
without dependency resolution, and runs strict mypy plus the coverage gate on
Python 3.11, 3.12, and 3.13. Separate jobs enforce the dependency lock, Ruff,
function documentation, live calibration, distribution build/wheel smoke, and
Foundry v1.7.1 tests with Solidity 0.8.28. A weekly read-only job audits the lock
and blocks unreviewed upstream-spec drift.

Run the full local gate from the repository root:

```bash
python -m pip install --require-hashes -r requirements/ci.txt
python -m pip install --no-deps --no-build-isolation -e .
python -m pip check
python -m ruff check src tests tools
python -m ruff format --check src tests tools
python tools/check_function_docs.py
python -m mypy
python -m pytest -q --cov --cov-fail-under=85
python tools/verify_new_features.py
python -m build --no-isolation
python -m twine check dist/*
(cd onchain && forge build && forge test -vvv)
```

The isolated wheel-smoke procedure and dependency-update policy are defined in
[`supply-chain.md`](supply-chain.md).

## Targeted review checklist

1. Prove no challenge, flag, config, direct API, or redirect can bypass
   `SafetyPolicy` or cause mainnet signing/settlement.
2. Trace private-key lifetime and verify no secret reaches logs, errors, output,
   reports, fingerprints, or run records.
3. Confirm strict wire types reject coercion, malformed success evidence, and
   conflicting response fields.
4. Confirm each implemented check ID is unique, cataloged, spec-referenced, and
   cannot turn transport/suite failure into PASS.
5. Audit resource identity, EIP-712 domain, payer, recipient, asset, amount,
   validity window, nonce, chain, transaction, and Transfer-log binding.
6. Review replay/race evidence carefully: a PASS is evidence from this run, not
   a proof that all implementations serialize safely under every load.
7. Threat-model DI-003 for DNS rebinding, mixed public/private DNS answers,
   IPv4/IPv6 special ranges, redirect loops/downgrades, response size, and caps.
8. Fuzz endpoint-controlled strings through JSON, Markdown, SARIF, console, and
   record output; verify URLs and exception messages stay sanitized.
9. Verify optional dependency absence fails with an explicit SKIP/error and
   never silently broadens a verdict.
10. Reconcile catalog count, support matrix, pinned commit, error registry, and
    report schema before approving a release.
11. Re-run build, wheel smoke, lock audit, calibration, and Foundry tests from a
    clean environment.

## Known limits

- The pinned baseline is intentionally older than current upstream; the support
  matrix records the reviewed drift. A pin change requires semantic review.
- Runnable positive settlement is EVM exact/EIP-3009 only and testnet/local only.
- SVM code builds partial transactions but makes no runnable conformance claim.
- Timing is noisy and advisory. Race PASS means no duplicate settlement was
  observed during that run.
- JP metadata checks are structural and arithmetic only, not tax or legal advice.
- Discovery live checks are bounded samples, not continuous monitoring.
- The tool must not be aimed at third-party systems without authorization and a
  current responsible-disclosure path.

## Production function index

Every function below has an inline docstring checked by
`tools/check_function_docs.py`. Qualified names show methods and nested helpers.

| File | Functions |
|---|---|
| `active.py` | `_retry_delay`; `ActiveResponse.served_resource`; `endpoint_crashed`; `settled_ok`; `_b64_json`; `parse_settlement`; `choose_eip3009_requirement`; `_response_from`; `build_active_context` and nested `_do`/`send`/`send_header`/`send_with_headers`; `preflight_resource_network`; `run_active_checks`; `run_timing_checks`; `run_payment_checks` |
| `checks/base.py` | `append_unique_check`; `register`; nested `decorator` |
| `checks/discovery.py` | `_CrossFetchAllowlist.parse`/`permits`; `_canonical_host`; `_system_resolver`; `_resolve_addresses`; `_is_public_address`; `_format_host_header`; `_validate_cross_fetch_target`; `_display_url`; `_SafeCrossFetcher.__call__`/`_reserve_request`/`_request`/`_request_pinned`; `_register`/`deco`; `_resources_url`; `_get_json`; `_is_int`; `_is_finite_number`; `_validate_requirement`; `_validate_discovery_body`; `di_001`; `_item_has_accept_value`; `_first_accept_value`; `_first_item_value`; `_first_extension`; `_filter_probes` and five nested matchers; `di_002`; `_accept_identity`; `di_003`; `evaluate_discovery`; `run_discovery_checks` |
| `checks/facilitator.py` | `_register`/`deco`; `_build_payload`; `_get_supported`; `fa_sup_001`; `fa_sup_002`; `_verify`; `_verify_raw`; `fa_ver_002`; `fa_ver_003`; `fa_ver_004`; `fa_err_001`; `_settle`; `evaluate_settle`/`mk`; `evaluate_facilitator`; `run_facilitator_checks` |
| `checks/handshake.py` | `hs_001` through `hs_007`; `_positive_max_age` |
| `checks/negative.py` | `_register`/`deco`; `_assert_rejected`; `_build_payload`; `neg_001`; `neg_002`; `neg_003`; `neg_004`; `neg_005`; `neg_006`; `neg_007`; `neg_008`; `neg_009`; `neg_011`; `neg_012`; `neg_013`; `neg_014`; `neg_015`; `sec_003`; `sec_004`; `sec_005`; `sec_006`; `sec_007`; `sec_010`; `sec_011`; `_run_active_check`; `evaluate_active` |
| `checks/payment.py` | `_result`; `_read_token_balance`; `_hex`; `_address_topic`; `_verify_transfer_logs`; `_verify_tx_onchain`; `evaluate_payment` |
| `checks/payment_required.py` | `_accepts_raw`; `_x402_version`; `_resource_identity`; `pr_001` through `pr_016` |
| `checks/timing.py` | `_mad`; `classify_timing`; `_result`; `_sample`; `evaluate_timing` |
| `cli.py` | `version`; `_facilitator_url_hint`; `_load_config`; `_config_error`; `_validate_check_config`; `_funded_signer_key`; `_config_default`; `_make_signer`; `_write_output`; `_emit`; `explain`; `diff`; `scan`; `check` and nested `_write_record`/`_progress`; `facilitator`; `discovery` |
| `diff.py` | `_index`; `DiffResult.has_regressions`; `DiffResult.unchanged`; `diff_reports`; `format_diff` and nested `_block` |
| `jp402.py` | `find_jp402_accept`; `find_jp402`; `_to_decimal`; `_is_power_of_ten`; `validate_tax`; `find_invoice_blocks` and nested `_invoice`; `validate_invoice` |
| `models.py` | `SettlementResponse.validate_transaction`; `VerifyResponse.validate_reason` |
| `payload_builder.py` | `_require_evm`; `_chain_id_from_caip2`; `EvmSigner.from_key`/`random`/`address`; `eip712_digest`; `build_exact_eip3009_payload`; `_sign_authorization`; `signature_recovers_to_authorizer`; six tamper/window helpers |
| `probe.py` | `Probe.legacy_headers_present`; `build_probe` |
| `redaction.py` | `sanitize_url`; `url_fingerprint`; `sanitize_text` |
| `report.py` | `summarize`; `exit_code`; `assessment_exit_code`; `_safe_results`; `to_json`; `_sarif_level`; `to_sarif`; `_md_cell`; `_md_inline_code`; `to_markdown`; `_explain_catalog`; `_explain_line`; `explain_check`; `to_developer_report` |
| `run_record.py` | `_redact_url`; `_clean_inputs`; `_content_hash`; `build_run_record`; `verify_run_record`; `write_run_record` |
| `runner.py` | `_is_paywall`; `_unreachable_reason`; `_request_with_transient_retry`; `_maybe_fetch_openapi`; `run_checks` |
| `safety.py` | `_network_chain_id`; `read_rpc_chain_id`; `SafetyPolicy.require_safe_network`; `SafetyPolicy.require_matching_rpc` |
| `scan.py` | `summarize_scan`; `rank_scan`; `format_scan`; `scan_to_dicts` |
| `svm.py` | `is_solana_network`; `is_known_token_program`; three instruction encoders; `derive_ata`; `build_exact_svm_transaction` |
| `tools/calibration_target.py` | `_break_checksum`; `_verify_payload`; `payment_required`; `_b64`; `_signature_recovers`; `make_handler` and handler response/request methods |
| `tools/check_function_docs.py` | `iter_python_files`; `missing_function_docstrings`; `check_function_docs`; `main` |
| `tools/mock_facilitator.py` | `Handler.do_GET`; `Handler.log_message` |
| `tools/onchain_facilitator.py` | `_b64`; `payment_required`; `_verify_offchain`; `_check_signature`; `_check_balance`; `_transfer_function`; `_check_unused_and_simulate`; `verify`; `settle`; handler response/request methods |
| `tools/onchain_smoke.py` | `balance`; `main`; nested `check` |
| `tools/verify_new_features.py` | `_check`; `_Server.__init__`/`__enter__`/`__exit__`; `by_id`; `main`; `_validate_schema` |

`__init__.py` and `checks/__init__.py` expose constants, types, and registry
imports but define no functions.

## Test-file scenario map

| Test files | Primary scenarios |
|---|---|
| `test_handshake.py`, `test_payment_required.py`, `test_probe.py`, `test_models.py` | passive handshake, strict decoding/types, identity, and schema validation |
| `test_negative.py`, `test_new_checks.py`, `test_active_retry.py`, `test_timing.py` | signed semantic negatives, robustness, leak detection, retries, and timing classification |
| `test_payment.py`, `test_onchain_facilitator.py`, `test_facilitator_eoa.py` | exact settlement evidence, receipt/log binding, replay/race, EOA-asset behavior |
| `test_facilitator.py`, `test_error_reason_drift.py` | strict supported/verify/settle responses and upstream error registry |
| `test_discovery.py`, `test_scan.py` | discovery schema/filters, SSRF boundaries, redirect/cap behavior, scan aggregation |
| `test_cli.py`, `test_cli_config.py`, `test_cli_exit_codes.py` | command routing, consent/config validation, stable exit semantics |
| `test_report.py`, `test_developer_report.py`, `test_sarif.py`, `test_diff.py`, `test_explain.py` | report schema/sanitization, alternate formats, catalog explanation and regression diffs |
| `test_run_record.py`, `test_safety.py` | secret redaction, integrity checks, network/RPC policy, redirect denial |
| `test_payload_builder.py`, `test_eth_account_pin.py` | EIP-712 equivalence, payload/tamper primitives, dependency surface pin |
| `test_jp402_unit.py`, `test_openapi_notes.py` | JP tax/invoice structures, hostile numerics, OpenAPI fetch diagnostics |
| `test_svm_foundation.py`, `test_svm_builder.py`, `test_svm_tamper.py` | SVM CAIP/program rules, ATA/instruction/transaction construction and tampering |
| `test_registry.py`, `test_function_docs.py` | duplicate/catalog drift and complete production-function documentation |

Fixtures under `tests/fixtures/jp402/` are structural reference data. Solidity
behavior is covered separately by `onchain/test/MockUSDC.t.sol` for metadata,
mint accounting, invalid signatures, expiry, and nonce preservation.
