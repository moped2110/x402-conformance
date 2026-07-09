"""CLI: x402-conformance."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import httpx
import typer

from . import SPEC_BASELINE, __version__
from .checks import CheckResult, Status
from .diff import diff_reports, format_diff
from .report import (
    exit_code,
    explain_check,
    summarize,
    to_developer_report,
    to_json,
    to_markdown,
    to_sarif,
)
from .run_record import DEFAULT_LOG_DIR, NO_LOG_ENV
from .runner import run_checks
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
    return sect if isinstance(sect, dict) else {}


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
    return EvmSigner.from_key(key) if key else EvmSigner.random()


def _emit(
    results: list[CheckResult],
    target: str,
    quiet: bool,
    json_out: Path | None,
    md_out: Path | None,
    developer: bool = False,
    sarif_out: Path | None = None,
) -> int:
    """Print results + write reports. Returns the CI exit code."""
    code = exit_code(results)
    if developer:
        # Failures-only punch-list for the endpoint owner: what's wrong + how to fix.
        typer.echo(to_developer_report(results, target))
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
                    line += f"\n      ↳ {r.detail}"
                typer.echo(line)
        s = summarize(results)
        verdict = (
            typer.style("CONFORMANT", fg=typer.colors.GREEN, bold=True)
            if code == 0
            else typer.style("NOT CONFORMANT", fg=typer.colors.RED, bold=True)
        )
        typer.echo(
            f"\n{verdict} — {s['passed']} passed, {s['failed']} failed, "
            f"{s['skipped']} skipped, {s['errors']} errors  ({target})"
        )
    if json_out is not None:
        json_out.write_text(to_json(results, target), encoding="utf-8")
        typer.echo(f"JSON report: {json_out}")
    if md_out is not None:
        md_out.write_text(to_markdown(results, target), encoding="utf-8")
        typer.echo(f"Markdown report: {md_out}")
    if sarif_out is not None:
        sarif_out.write_text(to_sarif(results, target), encoding="utf-8")
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
    signer_key: str | None = typer.Option(
        None,
        "--signer-key",
        help="Throwaway testnet key for --resource negatives "
        "(default: $X402_TESTNET_PAYER_KEY or random).",
    ),
    timeout: float = typer.Option(10.0, "--timeout", help="Per-request timeout in seconds"),
    json_out: Path | None = typer.Option(None, "--json", help="Write the ranked scan JSON"),
) -> None:
    """Batch-scan many facilitator URLs (PASSIVE) and rank them by findings — recon.

    Never settles and moves no funds. Prints a table with the most non-conformant
    facilitators first. Exit 1 if any reachable target is non-conformant, else 0.
    """
    from .checks.facilitator import run_facilitator_checks

    raw = targets.read_text(encoding="utf-8").splitlines()
    urls = [ln.strip() for ln in raw if ln.strip() and not ln.strip().startswith("#")]
    if not urls:
        typer.secho("no target URLs found in file", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)

    signer = _make_signer(signer_key) if resource else None
    entries: list[ScanEntry] = []
    for url in urls:
        try:
            results = run_facilitator_checks(
                url, resource_url=resource, signer=signer, allow_settle=False, timeout=timeout
            )
            entries.append(summarize_scan(url, results))
        except httpx.HTTPError as exc:
            entries.append(ScanEntry(url=url, unreachable=str(exc)))

    typer.echo(format_scan(entries))
    if json_out is not None:
        json_out.write_text(json.dumps(scan_to_dicts(entries), indent=2), encoding="utf-8")
        typer.echo(f"JSON report: {json_out}")

    reachable = [e for e in entries if e.unreachable is None]
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
        help="Directory for the tamper-evident JSON run record + runs.jsonl journal. "
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

    Exit code 0: conformant (no major/critical failures). Exit code 1: not
    conformant. Exit code 2: target unreachable.
    """
    cfg = _load_config(config, "check")
    method = str(_config_default(ctx, cfg, "method", method))
    timeout = float(cast(float, _config_default(ctx, cfg, "timeout", timeout)))
    active = bool(_config_default(ctx, cfg, "active", active))
    resource_marker = cast(
        "str | None", _config_default(ctx, cfg, "resource_marker", resource_marker)
    )
    pay = bool(_config_default(ctx, cfg, "pay", pay))
    rpc_url = cast("str | None", _config_default(ctx, cfg, "rpc_url", rpc_url))
    concurrency = int(cast(int, _config_default(ctx, cfg, "concurrency", concurrency)))
    progress = bool(_config_default(ctx, cfg, "progress", progress))
    fix = bool(_config_default(ctx, cfg, "fix", fix))
    quiet = bool(_config_default(ctx, cfg, "quiet", quiet))
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
        path = write_run_record(record, run_log_dir)
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
        signer = _make_signer(signer_key)
        if signer is not None:
            signer_address = getattr(signer, "address", None)
            from .active import run_payment_checks

            results = results + run_payment_checks(url, signer, rpc_url=rpc_url, method=method)

    _write_record(results)

    raise typer.Exit(
        _emit(results, url, quiet, json_out, md_out, developer=fix, sarif_out=sarif_out)
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

    signer = _make_signer(signer_key) if resource else None
    try:
        results = run_facilitator_checks(
            url, resource_url=resource, signer=signer, allow_settle=settle, timeout=timeout
        )
    except httpx.HTTPError as exc:
        typer.secho(f"facilitator unreachable: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from exc

    raise typer.Exit(_emit(results, url, quiet, json_out, md_out, sarif_out=sarif_out))


@app.command()
def discovery(
    url: str = typer.Argument(..., help="Discovery/Bazaar base URL (exposes /discovery/resources)"),
    timeout: float = typer.Option(10.0, "--timeout", help="Request timeout in seconds"),
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
        results = run_discovery_checks(url, timeout=timeout)
    except httpx.HTTPError as exc:
        typer.secho(f"discovery endpoint unreachable: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from exc

    raise typer.Exit(_emit(results, url, quiet, json_out, md_out, sarif_out=sarif_out))


if __name__ == "__main__":
    app()
