"""CLI: x402-conformance."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import httpx
import typer

from . import SPEC_BASELINE, __version__
from .checks import CheckResult, Status
from .report import exit_code, summarize, to_developer_report, to_json, to_markdown
from .runner import run_checks

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


def _make_signer(signer_key: Optional[str]) -> Optional[object]:
    """Build an EVM signer (throwaway by default). Returns None if eth-account is missing."""
    try:
        from .payload_builder import EvmSigner
    except Exception as exc:  # pragma: no cover
        typer.secho(f"signing unavailable ({exc}); install x402-conformance[evm]",
                    fg=typer.colors.YELLOW, err=True)
        return None
    key = signer_key or os.environ.get("X402_TESTNET_PAYER_KEY")
    return EvmSigner.from_key(key) if key else EvmSigner.random()


def _emit(
    results: list[CheckResult], target: str, quiet: bool,
    json_out: Optional[Path], md_out: Optional[Path], developer: bool = False,
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
    return code


@app.command()
def check(
    url: str = typer.Argument(..., help="x402-protected endpoint URL to test"),
    method: str = typer.Option("GET", "--method", "-m", help="HTTP method for the probe"),
    timeout: float = typer.Option(10.0, "--timeout", help="Request timeout in seconds"),
    active: bool = typer.Option(
        False, "--active", "-a",
        help="Also run active negative checks (RS-NEG): sends deliberately-invalid "
             "payments and verifies they are rejected. Uses a throwaway signer; never mainnet.",
    ),
    signer_key: Optional[str] = typer.Option(
        None, "--signer-key", help="Testnet throwaway private key for --active "
        "(default: $X402_TESTNET_PAYER_KEY or a random key)",
    ),
    resource_marker: Optional[str] = typer.Option(
        None, "--resource-marker", help="A unique string from the protected resource "
        "body. With --active, a rejected response that still contains it is flagged "
        "as a content leak (RS-SEC-009).",
    ),
    pay: bool = typer.Option(
        False, "--pay",
        help="Run the positive settlement path (RS-PAY): sends ONE valid, funded "
             "payment that settles ON-CHAIN. MOVES REAL FUNDS — needs a funded "
             "--signer-key. Use only against a testnet/Anvil.",
    ),
    rpc_url: Optional[str] = typer.Option(
        None, "--rpc-url", help="RPC URL to verify the settlement tx on-chain (RS-PAY-004)",
    ),
    json_out: Optional[Path] = typer.Option(None, "--json", help="Write JSON report to file"),
    md_out: Optional[Path] = typer.Option(None, "--markdown", help="Write Markdown report to file"),
    fix: bool = typer.Option(
        False, "--fix",
        help="Print a developer-focused report instead of the full table: failures "
             "only, grouped by severity, each with what's wrong, how to fix, and the spec ref.",
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Only print the summary line"),
) -> None:
    """Run conformance checks against a resource endpoint URL.

    Exit code 0: conformant (no major/critical failures). Exit code 1: not
    conformant. Exit code 2: target unreachable.
    """
    try:
        results = run_checks(url, method=method, timeout=timeout)
    except httpx.HTTPError as exc:
        typer.secho(f"target unreachable: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)

    if resource_marker and not active:
        typer.secho("note: --resource-marker has no effect without --active (it guards "
                    "the active rejection path)", fg=typer.colors.YELLOW, err=True)

    if active:
        signer = _make_signer(signer_key)
        if signer is not None:
            from .active import run_active_checks
            results = results + run_active_checks(
                url, signer, method=method, timeout=timeout, resource_marker=resource_marker
            )

    if pay:
        signer = _make_signer(signer_key)
        if signer is not None:
            from .active import run_payment_checks
            results = results + run_payment_checks(url, signer, rpc_url=rpc_url, method=method)

    raise typer.Exit(_emit(results, url, quiet, json_out, md_out, developer=fix))


@app.command()
def facilitator(
    url: str = typer.Argument(..., help="Facilitator base URL (exposes /supported, /verify, /settle)"),
    resource: Optional[str] = typer.Option(
        None, "--resource", help="An x402 resource URL to source real requirements "
        "from, enabling the /verify negative checks (FA-VER/FA-ERR).",
    ),
    signer_key: Optional[str] = typer.Option(
        None, "--signer-key", help="Testnet throwaway private key (default: "
        "$X402_TESTNET_PAYER_KEY or random); only used with --resource.",
    ),
    settle: bool = typer.Option(
        False, "--settle",
        help="Also run FA-SET /settle tests (valid settle, invalid settle, "
             "double-settle). MOVES REAL FUNDS — testnet/Anvil only, needs a funded signer.",
    ),
    timeout: float = typer.Option(10.0, "--timeout", help="Request timeout in seconds"),
    json_out: Optional[Path] = typer.Option(None, "--json", help="Write JSON report to file"),
    md_out: Optional[Path] = typer.Option(None, "--markdown", help="Write Markdown report to file"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Only print the summary line"),
) -> None:
    """Run facilitator conformance checks (FA-*) against a facilitator base URL."""
    from .checks.facilitator import run_facilitator_checks

    signer = _make_signer(signer_key) if resource else None
    try:
        results = run_facilitator_checks(url, resource_url=resource, signer=signer,
                                         allow_settle=settle, timeout=timeout)
    except httpx.HTTPError as exc:
        typer.secho(f"facilitator unreachable: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)

    raise typer.Exit(_emit(results, url, quiet, json_out, md_out))


@app.command()
def discovery(
    url: str = typer.Argument(..., help="Discovery/Bazaar base URL (exposes /discovery/resources)"),
    timeout: float = typer.Option(10.0, "--timeout", help="Request timeout in seconds"),
    json_out: Optional[Path] = typer.Option(None, "--json", help="Write JSON report to file"),
    md_out: Optional[Path] = typer.Option(None, "--markdown", help="Write Markdown report to file"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Only print the summary line"),
) -> None:
    """Run discovery conformance checks (DI-*) against a Bazaar base URL."""
    from .checks.discovery import run_discovery_checks

    try:
        results = run_discovery_checks(url, timeout=timeout)
    except httpx.HTTPError as exc:
        typer.secho(f"discovery endpoint unreachable: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)

    raise typer.Exit(_emit(results, url, quiet, json_out, md_out))


if __name__ == "__main__":
    app()
