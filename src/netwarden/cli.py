"""Command line interface."""

from __future__ import annotations

from pathlib import Path

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

from netwarden.config import ConfigError, NetWardenConfig, load_config
from netwarden.inventory import Inventory

app = typer.Typer(help="NetWarden - SNMP-based network health monitor", no_args_is_help=True)
console = Console()

ConfigOpt = typer.Option(
    Path("config.yaml"), "--config", "-c", envvar="NETWARDEN_CONFIG", help="Path to config file"
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


if __name__ == "__main__":
    app()
