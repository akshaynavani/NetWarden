"""Command line interface."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Optional

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

from netwarden.config import ConfigError, NetWardenConfig, load_config
from netwarden.inventory import Inventory, TargetNotAllowed
from netwarden.models import Severity
from netwarden.remediation import RemediationExecutor, plan_remediation
from netwarden.reports import (
    build_report,
    cycle_from_results,
    render_console,
    render_json,
    render_markdown,
)
from netwarden.runner import Runner
from netwarden.state import StateStore

app = typer.Typer(help="NetWarden - SNMP-based network health monitor", no_args_is_help=True)
console = Console()

ConfigOpt = typer.Option(
    Path("config.yaml"), "--config", "-c", envvar="NETWARDEN_CONFIG", help="Path to config file"
)


HostOpt = typer.Option(None, "--host", "-H", help="Limit to these host names (repeatable)")
TagOpt = typer.Option(None, "--tag", "-t", help="Limit to hosts with any of these tags")


@app.callback()
def main(verbose: bool = typer.Option(False, "--verbose", "-v", help="Debug logging")) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _load(path: Path) -> NetWardenConfig:
    load_dotenv()
    try:
        return load_config(path)
    except ConfigError as exc:
        console.print(f"[red]Config error:[/red] {exc}")
        raise typer.Exit(2) from exc


@app.command("validate-config")
def validate_config(config: Path = ConfigOpt) -> None:
    """Parse and validate the configuration file."""
    cfg = _load(config)
    remediation = "enabled" if cfg.remediation.enabled else "disabled (dry-run only)"
    console.print(f"[green]OK[/green] {len(cfg.hosts)} host(s); remediation {remediation}")


@app.command()
def hosts(config: Path = ConfigOpt) -> None:
    """List the hosts NetWarden is allowed to monitor."""
    inv = Inventory(_load(config))
    table = Table(title="Monitored hosts")
    table.add_column("Name")
    table.add_column("Address")
    table.add_column("Tags")
    table.add_column("Checks")
    table.add_column("Remediation actions")
    for host in inv:
        table.add_row(
            host.name,
            host.address,
            ", ".join(host.tags),
            ", ".join(host.checks.enabled()),
            ", ".join(host.remediation.allowed_actions) or "-",
        )
    console.print(table)


def _select(inv: Inventory, hosts: Optional[list[str]], tags: Optional[list[str]]):
    try:
        selected = inv.select(hosts, tags)
    except TargetNotAllowed as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc
    if not selected:
        console.print("[yellow]No hosts match the selection.[/yellow]")
        raise typer.Exit(1)
    return selected


@app.command()
def check(
    config: Path = ConfigOpt,
    host: Optional[list[str]] = HostOpt,
    tag: Optional[list[str]] = TagOpt,
    output: str = typer.Option("console", "--output", "-o", help="console | json | markdown"),
    plan: bool = typer.Option(
        False, "--plan-remediation", help="Also generate dry-run remediation scripts"
    ),
) -> None:
    """Run one poll cycle against the configured hosts and print a report.

    Exit code: 0 = all ok, 1 = warnings, 2 = critical findings.
    """
    inv = Inventory(_load(config))
    hosts = _select(inv, host, tag)
    runner = Runner(inv)
    cycle, _, report = asyncio.run(runner.run_cycle(hosts))
    _print_report(report, output)
    if plan:
        _remediate(inv, cycle.findings, apply=False)
    runner.store.close()
    raise typer.Exit({Severity.OK: 0, Severity.WARNING: 1, Severity.CRITICAL: 2}[cycle.worst])


@app.command()
def run(
    config: Path = ConfigOpt,
    host: Optional[list[str]] = HostOpt,
    tag: Optional[list[str]] = TagOpt,
) -> None:
    """Poll continuously every `polling.interval_seconds` until interrupted."""
    inv = Inventory(_load(config))
    hosts = _select(inv, host, tag)
    console.print(
        f"Monitoring {len(hosts)} host(s) every {inv.config.polling.interval_seconds}s "
        f"(remediation {'enabled' if inv.config.remediation.enabled else 'disabled'})"
    )
    asyncio.run(Runner(inv).run_forever(hosts))


@app.command()
def report(
    config: Path = ConfigOpt,
    output: str = typer.Option("console", "--output", "-o", help="console | json | markdown"),
) -> None:
    """Render a report from the most recent stored results (no polling)."""
    cfg = _load(config)
    inv = Inventory(cfg)
    store = StateStore(cfg.storage.sqlite_path)
    results = [r for r in store.latest_results() if r.host in {h.name for h in inv}]
    if not results:
        console.print("[yellow]No stored results yet - run `netwarden check` first.[/yellow]")
        raise typer.Exit(1)
    runner = Runner(inv, store=store, notifiers=[])
    findings = runner.evaluate_results(results, use_history=False)
    rep = build_report(cycle_from_results(results, findings), store.open_alerts())
    _print_report(rep, output)
    store.close()


@app.command()
def remediate(
    config: Path = ConfigOpt,
    host: Optional[list[str]] = HostOpt,
    apply: bool = typer.Option(
        False, "--apply", help="Actually execute actions (requires remediation.enabled)"
    ),
) -> None:
    """Plan remediation for current problems. Dry run unless --apply is given."""
    cfg = _load(config)
    inv = Inventory(cfg)
    wanted = {h.name for h in _select(inv, host, None)}
    store = StateStore(cfg.storage.sqlite_path)
    results = [r for r in store.latest_results() if r.host in wanted]
    runner = Runner(inv, store=store, notifiers=[])
    findings = runner.evaluate_results(results, use_history=False)
    store.close()
    if apply and not cfg.remediation.enabled:
        console.print(
            "[red]--apply given but remediation.enabled is false; falling back to dry run.[/red]"
        )
        apply = False
    _remediate(inv, findings, apply=apply)


def _remediate(inv: Inventory, findings, apply: bool) -> None:
    actions = plan_remediation(inv, findings)
    if not actions:
        console.print("No remediation actions planned.")
        return
    executor = RemediationExecutor(inv, inv.config.remediation)
    records = asyncio.run(executor.execute(actions, apply=apply))
    table = Table(title="Remediation" + (" (APPLY)" if apply else " (dry run)"))
    for col in ("Host", "Action", "Mode", "Script", "Note"):
        table.add_column(col)
    for rec in records:
        table.add_row(
            rec.action.host,
            rec.action.action,
            rec.mode,
            str(rec.script) if rec.script else "-",
            rec.note or (f"exit {rec.exit_code}" if rec.exit_code is not None else ""),
        )
    console.print(table)


def _print_report(rep: dict, output: str) -> None:
    if output == "json":
        typer.echo(render_json(rep))
    elif output == "markdown":
        typer.echo(render_markdown(rep))
    else:
        render_console(rep, console)


if __name__ == "__main__":
    app()
