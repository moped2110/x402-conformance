"""CLI: x402-conformance."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit

import httpx
import typer

from . import SPEC_BASELINE, __version__
from .checks import CheckResult, Status
from .diff import diff_reports, format_diff
from .redaction import sanitize_text, sanitize_url
from .report import (
    assessment_exit_code,
    explain_check,
    summarize,
    to_developer_report,
    to_json,
    to_markdown,
    to_sarif,
)
from .run_record import DEFAULT_LOG_DIR, NO_LOG_ENV
from .runner import run_checks
from .safety import SafetyViolation
from .scan import ScanEntry, format_scan, scan_to_dicts, summarize_scan

app = typer.Typer(
    name="x402-conformance",
    help="Black-box conformance testing for x402 payment endpoints.",
    add_completion=False,
    no_args_is_help=True,
)


@app.command()
def version() -> None:
    """Print version and pinned spec baseline."""
    typer.echo(f"x402-conformance {__version__}")
    typer.echo(f"spec baseline: {SPEC_BASELINE}")


_DEFAULT_CONFIG_NAME = ".x402-conformance.toml"

#: Path suffixes that mark a facilitator/discovery endpoint rather than a paywalled
#: resource. Pointing the passive resource `check` at these yields a false RS-HS-001
#: (a facilitator's /supported correctly returns 200, not 402) — so we warn instead.
_FACILITATOR_PATH_HINTS = ("/supported", "/verify", "/settle")


def _facilitator_url_hint(url: str) -> str | None:
    """Return a nudge if ``url`` looks like a facilitator/discovery endpoint, so the
    user runs the right subcommand instead of getting a spurious resource finding."""
    path = urlsplit(url).path.lower().rstrip("/")
    if path.endswith("/.well-known/x402"):
        return (
            "this looks like an x402 discovery document (.well-known/x402), not a "
            "paywalled resource — a passive 'check' will report a false RS-HS-001"
        )
    for hint in _FACILITATOR_PATH_HINTS:
        if path.endswith(hint):
            return (
                f"this looks like a facilitator endpoint ({hint}) — it correctly answers "
                "200, not 402; use the 'facilitator' subcommand to test it instead"
            )
    return None


def _load_config(explicit: Path | None, section: str) -> dict[str, object]:
    """Load `[section]` from a TOML config. With no --config, auto-discover
    ``.x402-conformance.toml`` in the current directory (absent → no defaults).
    An explicitly-given --config that's missing or malformed is a hard error (2).

    Note: secrets (e.g. --signer-key) are intentionally NOT read from config — keep
    keys in the environment, never in a file that might be committed.
    """
    import tomllib

    path = explicit or Path(_DEFAULT_CONFIG_NAME)
    if not path.exists():
        if explicit is not None:
            typer.secho(f"config file not found: {path}", fg=typer.colors.RED, err=True)
            raise typer.Exit(2)
        return {}
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError) as exc:
        typer.secho(f"cannot read config {path}: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from exc
    sect = data.get(section)
    if sect is None:
        return {}
    if not isinstance(sect, dict):
        typer.secho(f"config [{section}] must be a TOML table", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)
    return sect


_CHECK_CONFIG_KEYS = frozenset(
    {
        "method",
        "timeout",
        "active",
        "resource_marker",
        "pay",
        "rpc_url",
        "timing",
        "concurrency",
        "progress",
        "fix",
        "quiet",
        "log_dir",
    }
)


def _config_error(message: str) -> None:
    typer.secho(f"invalid [check] config: {message}", fg=typer.colors.RED, err=True)
    raise typer.Exit(2)


def _validate_check_config(cfg: dict[str, object]) -> dict[str, object]:
    """Validate TOML types before applying them to Typer-parsed CLI values.

    In particular, ``bool('false')`` must never enable a payment mode.  Modes
    that sign payment material require an explicit flag on every invocation and
    therefore cannot be enabled by an auto-discovered config file.
    """

    unknown = sorted(set(cfg) - _CHECK_CONFIG_KEYS)
    if unknown:
        _config_error(f"unknown key(s): {', '.join(unknown)}")

    for name in ("active", "pay", "timing", "progress", "fix", "quiet"):
        if name in cfg and type(cfg[name]) is not bool:
            _config_error(f"{name} must be a boolean")
    for name in ("active", "pay", "timing"):
        if cfg.get(name) is True:
            _config_error(f"{name} cannot be enabled from config; pass --{name} explicitly")

    if "method" in cfg and (not isinstance(cfg["method"], str) or not cfg["method"].strip()):
        _config_error("method must be a non-empty string")
    if "timeout" in cfg:
        value = cfg["timeout"]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= 300:
            _config_error("timeout must be a number greater than 0 and at most 300")
    if "concurrency" in cfg:
        value = cfg["concurrency"]
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 64:
            _config_error("concurrency must be an integer from 1 to 64")
    for name in ("resource_marker", "rpc_url", "log_dir"):
        if name in cfg and not isinstance(cfg[name], str):
            _config_error(f"{name} must be a string")
    return cfg


def _funded_signer_key(signer_key: str | None) -> str:
    """Require an explicitly supplied testnet payer for money-moving modes."""

    key = signer_key or os.environ.get("X402_TESTNET_PAYER_KEY")
    if not key:
        typer.secho(
            "a funded testnet signer is required; pass --signer-key or set X402_TESTNET_PAYER_KEY",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(2)
    return key


def _config_default(
    ctx: typer.Context, cfg: dict[str, object], name: str, current: object
) -> object:
    """Return the config value for ``name`` only when the CLI flag was left at its
    default — an explicit CLI flag always wins over the config file.

    We read the parameter *source* enum by name ("DEFAULT") rather than importing
    click's ParameterSource: some Typer builds don't expose `click` as an
    importable top-level module.
    """
    if name not in cfg:
        return current
    source = ctx.get_parameter_source(name)
    if source is None or getattr(source, "name", "") == "DEFAULT":
        return cfg[name]
    return current


def _make_signer(signer_key: str | None) -> object | None:
    """Build an EVM signer (throwaway by default). Returns None if eth-account is missing."""
    try:
        from .payload_builder import EvmSigner
    except Exception as exc:  # pragma: no cover
        typer.secho(
            f"signing unavailable ({exc}); install x402-conformance[evm]",
            fg=typer.colors.YELLOW,
            err=True,
        )
        return None
    key = signer_key or os.environ.get("X402_TESTNET_PAYER_KEY")
    try:
        return EvmSigner.from_key(key) if key else EvmSigner.random()
    except (TypeError, ValueError) as exc:
        raise typer.BadParameter("invalid EVM testnet signer key") from exc


def _write_output(path: Path, content: str, label: str) -> None:
    """Write a CLI artifact, translating filesystem failures to exit code 2."""
    try:
        path.write_text(content, encoding="utf-8")
    except OSError as exc:
        typer.secho(f"cannot write {label}: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from exc


def _emit(
    results: list[CheckResult],
    target: str,
    quiet: bool,
    json_out: Path | None,
    md_out: Path | None,
    developer: bool = False,
    sarif_out: Path | None = None,
    outcome_code: int | None = None,
) -> int:
    """Print results + write reports. Returns the CI exit code."""
    code = assessment_exit_code(results) if outcome_code is None else outcome_code
    safe_target = sanitize_url(target) or "<redacted>"
    if developer:
        # Failures-only punch-list for the endpoint owner: what's wrong + how to fix.
        typer.echo(to_developer_report(results, target, code))
    else:
        if not quiet:
            icon = {
                Status.PASS: typer.style("PASS", fg=typer.colors.GREEN),
                Status.FAIL: typer.style("FAIL", fg=typer.colors.RED),
                Status.SKIP: typer.style("SKIP", fg=typer.colors.YELLOW),
                Status.ERROR: typer.style("ERR ", fg=typer.colors.MAGENTA),
            }
            for r in results:
                line = f"{icon[r.status]}  {r.check_id:<10} [{r.severity.value:<8}] {r.title}"
                if r.detail and r.status != Status.PASS:
                    detail = sanitize_text(r.detail, sensitive_values=(target,)) or ""
                    line += f"\n      ↳ {detail}"
                typer.echo(line)
        s = summarize(results)
        verdict = (
            typer.style("CONFORMANT", fg=typer.colors.GREEN, bold=True)
            if code == 0
            else typer.style("INCONCLUSIVE", fg=typer.colors.YELLOW, bold=True)
            if code == 2
            else typer.style("NOT CONFORMANT", fg=typer.colors.RED, bold=True)
        )
        typer.echo(
            f"\n{verdict} — {s['passed']} passed, {s['failed']} failed, "
            f"{s['skipped']} skipped, {s['errors']} errors  ({safe_target})"
        )
    if json_out is not None:
        _write_output(json_out, to_json(results, target, code), "JSON report")
        typer.echo(f"JSON report: {json_out}")
    if md_out is not None:
        _write_output(md_out, to_markdown(results, target, code), "Markdown report")
        typer.echo(f"Markdown report: {md_out}")
    if sarif_out is not None:
        _write_output(sarif_out, to_sarif(results, target, code), "SARIF report")
        typer.echo(f"SARIF report: {sarif_out}")
    return code


@app.command()
def explain(
    check_id: str | None = typer.Argument(
        None,
        help="A check ID (e.g. RS-NEG-007) or a prefix (e.g. RS-SEC). "
        "Omit to list the whole catalog.",
    ),
) -> None:
    """Explain what a check tests, why it matters, and how to fix a failure.

    Offline — reads the built-in check catalog, no target needed. Examples:
    `x402-conformance explain RS-NEG-007`, `explain FA`, or `explain` for the full list.
    """
    typer.echo(explain_check(check_id))


@app.command()
def diff(
    old: Path = typer.Argument(..., help="Previous JSON report (from --json)"),
    new: Path = typer.Argument(..., help="Current JSON report (from --json)"),
) -> None:
    """Compare two JSON reports — "did my fix work?".

    Classifies each check as fixed / regressed / still-failing / added / removed.
    Exit 0 if no previously-passing check regressed, 1 if any regressed, 2 on read error.
    """
    try:
        result = diff_reports(old.read_text(encoding="utf-8"), new.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        typer.secho(f"cannot diff: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from exc
    typer.echo(format_diff(result))
    raise typer.Exit(1 if result.has_regressions else 0)


@app.command()
def scan(
    targets: Path = typer.Argument(
        ...,
        help="File of facilitator base URLs, one per line (blank lines and #comments ignored)",
    ),
    resource: str | None = typer.Option(
        None,
        "--resource",
        help="x402 resource URL to source requirements for the /verify "
        "negative checks (FA-VER/FA-ERR); without it only /supported is exercised.",
    ),
    authorize_active_verify: bool = typer.Option(
        False,
        "--authorize-active-verify",
        help="Explicitly authorize signed invalid /verify probes for every listed target. "
        "Required with --resource; never enables /settle.",
    ),
    signer_key: str | None = typer.Option(
        None,
        "--signer-key",
        help="Throwaway testnet key for --resource negatives "
        "(default: $X402_TESTNET_PAYER_KEY or random).",
    ),
    timeout: float = typer.Option(10.0, "--timeout", help="Per-request timeout in seconds"),
    json_out: Path | None = typer.Option(None, "--json", help="Write the ranked scan JSON"),
) -> None:
    """Batch-scan facilitators and rank findings; /verify probes require explicit consent.

    Without --resource this only reads /supported. With --resource it sends signed
    invalid payments to /verify, but never settles or moves funds. Exit 1 if any
    reachable target is non-conformant, else 0.
    """
    from .checks.facilitator import run_facilitator_checks

    try:
        raw = targets.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        typer.secho(f"cannot read targets file: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from exc
    urls = [ln.strip() for ln in raw if ln.strip() and not ln.strip().startswith("#")]
    if not urls:
        typer.secho("no target URLs found in file", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)

    if resource and not authorize_active_verify:
        typer.secho(
            "--resource sends active /verify probes; add --authorize-active-verify "
            "after confirming authorization for every target",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(2)
    if authorize_active_verify and not resource:
        typer.secho("--authorize-active-verify requires --resource", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)

    if resource:
        from .active import preflight_resource_network

        try:
            preflight_resource_network(resource, timeout=timeout)
        except (SafetyViolation, httpx.HTTPError) as exc:
            typer.secho(f"unsafe/unreachable resource: {exc}", fg=typer.colors.RED, err=True)
            raise typer.Exit(2) from exc
    signer = _make_signer(signer_key) if resource else None
    if resource:
        mode = "active /verify (signed invalid payments; no /settle)"
        request_scope = "up to 6 HTTP requests per target plus one resource safety preflight"
    else:
        mode = "read-only /supported"
        request_scope = "1 HTTP request per target"
    typer.echo(f"Scope: {mode}; {len(urls)} target(s); {request_scope}.")
    entries: list[ScanEntry] = []
    for url in urls:
        try:
            results = run_facilitator_checks(
                url, resource_url=resource, signer=signer, allow_settle=False, timeout=timeout
            )
            entries.append(summarize_scan(url, results))
        except httpx.HTTPError as exc:
            entries.append(
                ScanEntry(
                    url=sanitize_url(url) or "<redacted>",
                    unreachable=sanitize_text(str(exc), sensitive_values=(url,)),
                )
            )

    typer.echo(format_scan(entries))
    if json_out is not None:
        _write_output(json_out, json.dumps(scan_to_dicts(entries), indent=2), "scan JSON")
        typer.echo(f"JSON report: {json_out}")

    reachable = [e for e in entries if e.unreachable is None]
    if not reachable:
        raise typer.Exit(2)
    raise typer.Exit(1 if any(not e.conformant for e in reachable) else 0)


@app.command()
def check(
    ctx: typer.Context,
    url: str = typer.Argument(..., help="x402-protected endpoint URL to test"),
    config: Path | None = typer.Option(
        None,
        "--config",
        help=f"TOML config supplying defaults under a [check] table (default: "
        f"auto-discover ./{_DEFAULT_CONFIG_NAME}). Explicit CLI flags always win. "
        f"Secrets like --signer-key are never read from config.",
    ),
    method: str = typer.Option("GET", "--method", "-m", help="HTTP method for the probe"),
    timeout: float = typer.Option(10.0, "--timeout", help="Request timeout in seconds"),
    active: bool = typer.Option(
        False,
        "--active",
        "-a",
        help="Also run active negative checks (RS-NEG): sends deliberately-invalid "
        "payments and verifies they are rejected. Uses a throwaway signer; never mainnet.",
    ),
    signer_key: str | None = typer.Option(
        None,
        "--signer-key",
        help="Testnet throwaway private key for --active "
        "(default: $X402_TESTNET_PAYER_KEY or a random key)",
    ),
    resource_marker: str | None = typer.Option(
        None,
        "--resource-marker",
        help="A unique string from the protected resource "
        "body. With --active, a rejected response that still contains it is flagged "
        "as a content leak (RS-SEC-009).",
    ),
    pay: bool = typer.Option(
        False,
        "--pay",
        help="Run the positive settlement path (RS-PAY): sends ONE valid, funded "
        "payment that settles ON-CHAIN. MOVES REAL FUNDS — needs a funded "
        "--signer-key. Use only against a testnet/Anvil.",
    ),
    rpc_url: str | None = typer.Option(
        None,
        "--rpc-url",
        help="RPC URL to verify the settlement tx on-chain (RS-PAY-004). Also "
        "enables a read-only balance precheck: if the signer can't cover the "
        "amount, RS-PAY is skipped cleanly instead of sending a doomed payment.",
    ),
    timing: bool = typer.Option(
        False,
        "--timing",
        help="Opt-in RS-SEC-008 timing-oracle probe: checks whether rejection time "
        "leaks which validation failed. Advisory (MINOR), never gates the verdict; "
        "sends only invalid payments, no funds. Uses a throwaway signer.",
    ),
    json_out: Path | None = typer.Option(None, "--json", help="Write JSON report to file"),
    md_out: Path | None = typer.Option(None, "--markdown", help="Write Markdown report to file"),
    sarif_out: Path | None = typer.Option(
        None, "--sarif", help="Write SARIF 2.1.0 findings (GitHub code-scanning ingestible)"
    ),
    concurrency: int = typer.Option(
        1,
        "--concurrency",
        "-c",
        min=1,
        help="Run the --active checks on N threads (default 1 = sequential, "
        "deterministic). Results stay in catalog order. Use >1 only against your "
        "OWN endpoints — parallel payment attempts against a third party look like abuse.",
    ),
    progress: bool = typer.Option(
        False,
        "--progress",
        help="Print per-check progress to stderr as the --active checks run.",
    ),
    log_dir: Path | None = typer.Option(
        None,
        "--log-dir",
        help="Directory for the integrity-checksummed JSON run record + runs.jsonl journal. "
        "Logging is ON by default (writes to ./x402-runs); use this to change the path.",
    ),
    no_log: bool = typer.Option(
        False,
        "--no-log",
        help="Disable the run record for this run (logging is on by default).",
    ),
    fix: bool = typer.Option(
        False,
        "--fix",
        help="Print a developer-focused report instead of the full table: failures "
        "only, grouped by severity, each with what's wrong, how to fix, and the spec ref.",
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Only print the summary line"),
) -> None:
    """Run conformance checks against a resource endpoint URL.

    Exit code 0: assessed and conformant. Exit code 1: not conformant.
    Exit code 2: inconclusive, unreachable, or invalid input/output.
    """
    cfg = _validate_check_config(_load_config(config, "check"))
    method = str(_config_default(ctx, cfg, "method", method))
    timeout = float(cast(float, _config_default(ctx, cfg, "timeout", timeout)))
    active = bool(_config_default(ctx, cfg, "active", active))
    resource_marker = cast(
        "str | None", _config_default(ctx, cfg, "resource_marker", resource_marker)
    )
    pay = bool(_config_default(ctx, cfg, "pay", pay))
    rpc_url = cast("str | None", _config_default(ctx, cfg, "rpc_url", rpc_url))
    timing = bool(_config_default(ctx, cfg, "timing", timing))
    concurrency = int(cast(int, _config_default(ctx, cfg, "concurrency", concurrency)))
    progress = bool(_config_default(ctx, cfg, "progress", progress))
    fix = bool(_config_default(ctx, cfg, "fix", fix))
    quiet = bool(_config_default(ctx, cfg, "quiet", quiet))
    if pay and not rpc_url:
        typer.secho(
            "--pay requires --rpc-url for chain verification", fg=typer.colors.RED, err=True
        )
        raise typer.Exit(2)
    payment_signer_key = _funded_signer_key(signer_key) if pay else signer_key
    # Logging is ON by default (writes to ./x402-runs). An explicit --log-dir or a
    # config log_dir overrides the path; --no-log or the NO_LOG_ENV env var (used by
    # the test suite) suppresses the default. An explicit path always writes.
    _raw_log_dir = _config_default(ctx, cfg, "log_dir", log_dir)
    if no_log:
        run_log_dir: Path | None = None
    elif _raw_log_dir:
        run_log_dir = Path(str(_raw_log_dir))
    elif os.environ.get(NO_LOG_ENV):
        run_log_dir = None
    else:
        run_log_dir = Path(DEFAULT_LOG_DIR)

    hint = _facilitator_url_hint(url)
    if hint:
        typer.secho(f"note: {hint}", fg=typer.colors.YELLOW, err=True)

    started_at = datetime.now(UTC)
    signer_address: str | None = None

    def _write_record(
        res: list[CheckResult], *, error: str | None = None, ec: int | None = None
    ) -> None:
        if run_log_dir is None:
            return
        from .run_record import build_run_record, write_run_record

        record = build_run_record(
            command="check",
            target=url,
            inputs={
                "method": method,
                "timeout": timeout,
                "active": active,
                "pay": pay,
                "timing": timing,
                "concurrency": concurrency,
                "resource_marker": resource_marker,
                "rpc_url": rpc_url,
            },
            results=res,
            signer_address=signer_address,
            started_at=started_at,
            finished_at=datetime.now(UTC),
            error=error,
            override_exit_code=ec,
        )
        try:
            path = write_run_record(record, run_log_dir)
        except OSError as exc:
            typer.secho(f"cannot write run record: {exc}", fg=typer.colors.RED, err=True)
            raise typer.Exit(2) from exc
        typer.echo(f"Run record: {path}")

    try:
        results = run_checks(url, method=method, timeout=timeout)
    except httpx.HTTPError as exc:
        # A failed attempt is worth recording too — the audit trail wants to know we
        # tried to test this target at this time and it was unreachable.
        _write_record([], error=f"target unreachable: {exc}", ec=2)
        typer.secho(f"target unreachable: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from exc

    if resource_marker and not active:
        typer.secho(
            "note: --resource-marker has no effect without --active (it guards "
            "the active rejection path)",
            fg=typer.colors.YELLOW,
            err=True,
        )

    if active or pay or timing:
        from .active import preflight_resource_network

        try:
            preflight_resource_network(
                url,
                method=method,
                timeout=timeout,
                rpc_url=rpc_url,
                require_rpc=pay,
            )
        except (SafetyViolation, httpx.HTTPError) as exc:
            _write_record(results, error=f"payment safety check failed: {exc}", ec=2)
            typer.secho(f"payment safety check failed: {exc}", fg=typer.colors.RED, err=True)
            raise typer.Exit(2) from exc

    if active:
        signer = _make_signer(signer_key)
        if signer is not None:
            signer_address = getattr(signer, "address", None)
            from .active import run_active_checks

            def _progress(r: CheckResult, done: int, total: int) -> None:
                typer.secho(
                    f"[{done:>2}/{total}] {r.check_id:<10} {r.status.value}",
                    fg=typer.colors.BLUE,
                    err=True,
                )

            results = results + run_active_checks(
                url,
                signer,
                method=method,
                timeout=timeout,
                resource_marker=resource_marker,
                concurrency=concurrency,
                progress=_progress if progress else None,
            )

    if pay:
        signer = _make_signer(payment_signer_key)
        if signer is not None:
            signer_address = getattr(signer, "address", None)
            from .active import run_payment_checks

            results = results + run_payment_checks(url, signer, rpc_url=rpc_url, method=method)

    if timing:
        signer = _make_signer(signer_key)
        if signer is not None:
            signer_address = getattr(signer, "address", None)
            from .active import run_timing_checks

            results = results + run_timing_checks(url, signer, method=method, timeout=timeout)

    outcome_code = assessment_exit_code(results)
    _write_record(results, ec=outcome_code)

    raise typer.Exit(
        _emit(
            results,
            url,
            quiet,
            json_out,
            md_out,
            developer=fix,
            sarif_out=sarif_out,
            outcome_code=outcome_code,
        )
    )


@app.command()
def facilitator(
    url: str = typer.Argument(
        ..., help="Facilitator base URL (exposes /supported, /verify, /settle)"
    ),
    resource: str | None = typer.Option(
        None,
        "--resource",
        help="An x402 resource URL to source real requirements "
        "from, enabling the /verify negative checks (FA-VER/FA-ERR).",
    ),
    signer_key: str | None = typer.Option(
        None,
        "--signer-key",
        help="Testnet throwaway private key (default: "
        "$X402_TESTNET_PAYER_KEY or random); only used with --resource.",
    ),
    settle: bool = typer.Option(
        False,
        "--settle",
        help="Also run FA-SET /settle tests (valid settle, invalid settle, "
        "double-settle). MOVES REAL FUNDS — testnet/Anvil only, needs a funded signer.",
    ),
    rpc_url: str | None = typer.Option(
        None,
        "--rpc-url",
        help="RPC URL used to verify that --settle targets the advertised test chain.",
    ),
    timeout: float = typer.Option(10.0, "--timeout", help="Request timeout in seconds"),
    json_out: Path | None = typer.Option(None, "--json", help="Write JSON report to file"),
    md_out: Path | None = typer.Option(None, "--markdown", help="Write Markdown report to file"),
    sarif_out: Path | None = typer.Option(
        None, "--sarif", help="Write SARIF 2.1.0 findings (GitHub code-scanning ingestible)"
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Only print the summary line"),
) -> None:
    """Run facilitator conformance checks (FA-*) against a facilitator base URL."""
    from .checks.facilitator import run_facilitator_checks

    if settle and resource is None:
        typer.secho("--settle requires --resource", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)
    if settle and rpc_url is None:
        typer.secho("--settle requires --rpc-url", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)

    payment_signer_key = _funded_signer_key(signer_key) if settle else signer_key
    if resource:
        from .active import preflight_resource_network

        try:
            preflight_resource_network(
                resource,
                timeout=timeout,
                rpc_url=rpc_url,
                require_rpc=settle,
            )
        except (SafetyViolation, httpx.HTTPError) as exc:
            typer.secho(f"payment safety check failed: {exc}", fg=typer.colors.RED, err=True)
            raise typer.Exit(2) from exc

    signer = _make_signer(payment_signer_key) if resource else None
    try:
        results = run_facilitator_checks(
            url,
            resource_url=resource,
            signer=signer,
            allow_settle=settle,
            rpc_url=rpc_url,
            timeout=timeout,
        )
    except (SafetyViolation, httpx.HTTPError) as exc:
        typer.secho(f"facilitator unreachable: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from exc

    raise typer.Exit(_emit(results, url, quiet, json_out, md_out, sarif_out=sarif_out))


@app.command()
def discovery(
    url: str = typer.Argument(..., help="Discovery/Bazaar base URL (exposes /discovery/resources)"),
    timeout: float = typer.Option(10.0, "--timeout", help="Request timeout in seconds"),
    allow_cross_fetch: list[str] = typer.Option(
        [],
        "--allow-cross-fetch",
        help="Explicitly allow one private cross-fetch host, IP, or CIDR (repeatable). "
        "Unsafe destinations stay blocked by default.",
    ),
    json_out: Path | None = typer.Option(None, "--json", help="Write JSON report to file"),
    md_out: Path | None = typer.Option(None, "--markdown", help="Write Markdown report to file"),
    sarif_out: Path | None = typer.Option(
        None, "--sarif", help="Write SARIF 2.1.0 findings (GitHub code-scanning ingestible)"
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Only print the summary line"),
) -> None:
    """Run discovery conformance checks (DI-*) against a Bazaar base URL."""
    from .checks.discovery import run_discovery_checks

    try:
        results = run_discovery_checks(
            url, timeout=timeout, cross_fetch_allowlist=tuple(allow_cross_fetch)
        )
    except httpx.HTTPError as exc:
        typer.secho(f"discovery endpoint unreachable: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from exc

    raise typer.Exit(_emit(results, url, quiet, json_out, md_out, sarif_out=sarif_out))


if __name__ == "__main__":
    app()
