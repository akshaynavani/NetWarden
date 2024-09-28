"""Remediation script generation and (opt-in) execution.

Safety model -- an action only executes when ALL of these hold:

1. ``remediation.enabled: true`` in config,
2. the caller passes ``apply=True`` (``netwarden remediate --apply``),
3. the action is listed in the host's ``allowed_actions`` (enforced by the planner and
   re-checked here),
4. the host has an ``ssh_user`` configured.

Otherwise the generated script is written to disk for human review and a ``dry_run`` entry
is appended to the audit log.
"""

from __future__ import annotations

import asyncio
import json
import os
import shlex
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from netwarden.config import Host, RemediationConfig
from netwarden.inventory import Inventory
from netwarden.remediation.actions import PlannedAction


@dataclass
class ExecutionRecord:
    action: PlannedAction
    mode: str  # dry_run | applied | refused | failed
    script: Path | None
    exit_code: int | None = None
    output: str = ""
    note: str = ""


def ssh_argv(host: Host, cfg: RemediationConfig, remote_command: str) -> list[str]:
    argv = ["ssh", *cfg.ssh_options, "-p", str(host.remediation.ssh_port)]
    if cfg.ssh_key_path:
        argv += ["-i", os.path.expanduser(cfg.ssh_key_path)]
    argv += [f"{host.remediation.ssh_user}@{host.address}", "--", remote_command]
    return argv


def remote_command(action: PlannedAction) -> str:
    return " && ".join(action.commands)


def render_script(action: PlannedAction, host: Host, cfg: RemediationConfig) -> str:
    argv = ssh_argv(host, cfg, remote_command(action))
    generated = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return "\n".join(
        [
            "#!/usr/bin/env bash",
            f"# NetWarden remediation: {action.action}",
            f"# Host:      {host.name} ({host.address})",
            f"# Reason:    {action.reason}",
            f"# Summary:   {action.summary}",
            f"# Generated: {generated}",
            "# Review before running. Remote commands:",
            *(f"#   {c}" for c in action.commands),
            "set -euo pipefail",
            "",
            shlex.join(argv),
            "",
        ]
    )


class RemediationExecutor:
    def __init__(self, inventory: Inventory, cfg: RemediationConfig) -> None:
        self.inventory = inventory
        self.cfg = cfg

    def _write_script(self, action: PlannedAction, host: Host) -> Path:
        self.cfg.script_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = self.cfg.script_dir / f"{stamp}-{host.name}-{action.action}.sh"
        path.write_text(render_script(action, host, self.cfg))
        path.chmod(0o750)
        return path

    def _audit(self, record: ExecutionRecord) -> None:
        self.cfg.audit_log.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "host": record.action.host,
            "action": record.action.action,
            "reason": record.action.reason,
            "mode": record.mode,
            "script": str(record.script) if record.script else None,
            "commands": list(record.action.commands),
            "exit_code": record.exit_code,
            "output": record.output[-2000:],
            "note": record.note,
        }
        with self.cfg.audit_log.open("a") as fh:
            fh.write(json.dumps(entry) + "\n")

    def _refusal(self, action: PlannedAction, host: Host, apply: bool) -> str | None:
        if action.action not in host.remediation.allowed_actions:
            return f"action {action.action} not allowed for host {host.name}"
        if not apply:
            return None  # plain dry run, not a refusal
        if not self.cfg.enabled:
            return "remediation.enabled is false in config"
        if not host.remediation.ssh_user:
            return f"no ssh_user configured for host {host.name}"
        return None

    async def execute(self, actions: list[PlannedAction], apply: bool = False) -> list[ExecutionRecord]:
        records: list[ExecutionRecord] = []
        for action in actions:
            host = self.inventory.get(action.host)  # raises if not in inventory
            script = self._write_script(action, host)
            refusal = self._refusal(action, host, apply)
            if refusal is not None:
                record = ExecutionRecord(action, "refused", script, note=refusal)
            elif not apply:
                record = ExecutionRecord(action, "dry_run", script, note="dry run; script written")
            else:
                record = await self._run(action, host, script)
            self._audit(record)
            records.append(record)
        return records

    async def _run(self, action: PlannedAction, host: Host, script: Path) -> ExecutionRecord:
        argv = ssh_argv(host, self.cfg, remote_command(action))
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
        )
        try:
            out, _ = await asyncio.wait_for(
                proc.communicate(), timeout=self.cfg.command_timeout_seconds
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return ExecutionRecord(action, "failed", script, note="timed out")
        output = out.decode(errors="replace")
        mode = "applied" if proc.returncode == 0 else "failed"
        return ExecutionRecord(action, mode, script, exit_code=proc.returncode, output=output)
