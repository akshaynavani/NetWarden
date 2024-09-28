"""Structured health reports in JSON, Markdown and Rich console form."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from netwarden.models import Finding, PollCycle, ProbeResult, Severity
from netwarden.state import AlertRow

SEVERITY_ICON = {Severity.OK: "OK", Severity.WARNING: "WARN", Severity.CRITICAL: "CRIT"}


def host_status(findings: list[Finding]) -> dict[str, Severity]:
    status: dict[str, Severity] = {}
    for f in findings:
        current = status.get(f.host, Severity.OK)
        status[f.host] = f.severity if f.severity > current else current
    return status


def build_report(
    cycle: PollCycle, open_alerts: list[AlertRow] | None = None
) -> dict[str, Any]:
    by_host: dict[str, dict[str, Any]] = defaultdict(lambda: {"probes": {}, "findings": []})
    for r in cycle.results:
        by_host[r.host]["probes"][r.probe] = {
            "status": r.status.value,
            "duration_ms": r.duration_ms,
            "error": r.error,
            "metrics": r.metrics,
        }
    for f in cycle.findings:
        if f.severity != Severity.OK:
            by_host[f.host]["findings"].append(
                {
                    "check": f.check,
                    "severity": f.severity.value,
                    "message": f.message,
                    "value": f.value,
                    "threshold": f.threshold,
                }
            )
    statuses = host_status(cycle.findings)
    for host, entry in by_host.items():
        entry["status"] = statuses.get(host, Severity.OK).value

    counts = {s.value: 0 for s in Severity}
    for s in statuses.values():
        counts[s.value] += 1

    return {
        "generated_at": cycle.finished_at.isoformat(),
        "poll_started_at": cycle.started_at.isoformat(),
        "duration_s": round((cycle.finished_at - cycle.started_at).total_seconds(), 2),
        "overall": cycle.worst.value,
        "host_counts": counts,
        "hosts": dict(sorted(by_host.items())),
        "open_alerts": [
            {
                "host": a.host,
                "check": a.check_name,
                "severity": a.severity.value,
                "message": a.message,
                "since": a.first_seen.isoformat(),
            }
            for a in (open_alerts or [])
        ],
    }


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, default=str)


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# NetWarden health report",
        "",
        f"- Generated: {report['generated_at']}",
        f"- Overall: **{report['overall'].upper()}**",
        f"- Hosts: {report['host_counts']['ok']} ok, {report['host_counts']['warning']} warning,"
        f" {report['host_counts']['critical']} critical",
        "",
        "## Hosts",
        "",
        "| Host | Status | Probes | Issues |",
        "|------|--------|--------|--------|",
    ]
    for host, entry in report["hosts"].items():
        probes = ", ".join(f"{p}:{d['status']}" for p, d in entry["probes"].items())
        lines.append(
            f"| {host} | {entry['status'].upper()} | {probes} | {len(entry['findings'])} |"
        )

    issues = [(h, f) for h, e in report["hosts"].items() for f in e["findings"]]
    lines += ["", "## Findings", ""]
    if not issues:
        lines.append("No warnings or critical findings.")
    else:
        lines += ["| Severity | Host | Check | Detail |", "|---|---|---|---|"]
        order = {"critical": 0, "warning": 1}
        for host, f in sorted(issues, key=lambda x: (order.get(x[1]["severity"], 2), x[0])):
            lines.append(f"| {f['severity'].upper()} | {host} | `{f['check']}` | {f['message']} |")

    if report["open_alerts"]:
        lines += ["", "## Open alerts", "", "| Host | Check | Severity | Since |", "|---|---|---|---|"]
        for a in report["open_alerts"]:
            lines.append(f"| {a['host']} | `{a['check']}` | {a['severity']} | {a['since']} |")
    return "\n".join(lines) + "\n"


def render_console(report: dict[str, Any], console: Console | None = None) -> None:
    console = console or Console()
    styles = {"ok": "green", "warning": "yellow", "critical": "bold red"}
    table = Table(title=f"NetWarden - overall {report['overall'].upper()}")
    table.add_column("Host")
    table.add_column("Status")
    table.add_column("Probes")
    table.add_column("Top issue")
    for host, entry in report["hosts"].items():
        top = entry["findings"][0]["message"] if entry["findings"] else "-"
        probes = " ".join(f"{p}:{d['status']}" for p, d in entry["probes"].items())
        table.add_row(
            host, f"[{styles[entry['status']]}]{entry['status'].upper()}[/]", probes, top
        )
    console.print(table)


def write_reports(report: dict[str, Any], directory: Path) -> list[Path]:
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.fromisoformat(report["generated_at"]).strftime("%Y%m%dT%H%M%SZ")
    json_path = directory / f"report-{stamp}.json"
    md_path = directory / f"report-{stamp}.md"
    json_path.write_text(render_json(report))
    md_path.write_text(render_markdown(report))
    (directory / "latest.json").write_text(render_json(report))
    (directory / "latest.md").write_text(render_markdown(report))
    return [json_path, md_path]


def cycle_from_results(results: list[ProbeResult], findings: list[Finding]) -> PollCycle:
    """Build a PollCycle from stored data (used by `netwarden report`)."""
    stamps = [r.timestamp for r in results] or [datetime.now().astimezone()]
    return PollCycle(
        started_at=min(stamps), finished_at=max(stamps), results=results, findings=findings
    )
