import json

import pytest

from netwarden.config import parse_config
from netwarden.inventory import Inventory
from netwarden.models import Finding, Severity
from netwarden.remediation import RemediationExecutor, plan_remediation
from netwarden.remediation.actions import UnsafeParameter, safe


def _finding(host, check, sev=Severity.CRITICAL, **kw):
    return Finding(host=host, probe=check.split(".")[0], check=check, severity=sev,
                   message="problem", **kw)


def test_planner_maps_findings_to_allowed_actions(inventory):
    findings = [
        _finding("dns-01", "dns.record.a.example/A"),
        _finding("dns-01", "ntp.offset", Severity.WARNING),
        _finding("dns-01", "tcp.port.22"),  # no rule for this
    ]
    actions = {a.action: a for a in plan_remediation(inventory, findings)}
    assert set(actions) == {"restart_service", "flush_dns_cache", "ntp_step"}
    assert actions["restart_service"].params["service"] == "named"
    assert actions["flush_dns_cache"].commands == ("sudo rndc flush",)
    assert actions["ntp_step"].commands[0] == "sudo chronyc makestep"


def test_host_without_allowed_actions_gets_nothing(inventory):
    findings = [_finding("sw-01", "snmp.reachability"),
                _finding("sw-01", "snmp.if_status.1", context={"if_descr": "eth1"})]
    assert plan_remediation(inventory, findings) == []


def test_ok_findings_and_unknown_hosts_are_ignored(inventory):
    findings = [_finding("dns-01", "dns.record.x/A", Severity.OK), _finding("ghost", "ntp.offset")]
    assert plan_remediation(inventory, findings) == []


def test_duplicate_actions_are_collapsed(inventory):
    findings = [_finding("dns-01", "dns.record.a/A"), _finding("dns-01", "dns.record.b/A")]
    restarts = [a for a in plan_remediation(inventory, findings) if a.action == "restart_service"]
    assert len(restarts) == 1


def test_safe_rejects_shell_metacharacters():
    assert safe("eth0") == "eth0"
    with pytest.raises(UnsafeParameter):
        safe("eth0; reboot")


async def test_executor_defaults_to_dry_run(inventory, config):
    actions = plan_remediation(inventory, [_finding("dns-01", "dns.record.a/A")])
    executor = RemediationExecutor(inventory, config.remediation)
    records = await executor.execute(actions)  # apply defaults to False
    assert {r.mode for r in records} == {"dry_run"}
    for r in records:
        script = r.script.read_text()
        assert script.startswith("#!/usr/bin/env bash")
        assert "netops@192.0.2.10" in script
    entries = [json.loads(l) for l in config.remediation.audit_log.read_text().splitlines()]
    assert all(e["mode"] == "dry_run" for e in entries)


async def test_apply_is_refused_when_remediation_disabled(inventory, config):
    actions = plan_remediation(inventory, [_finding("dns-01", "ntp.offset")])
    records = await RemediationExecutor(inventory, config.remediation).execute(actions, apply=True)
    assert records[0].mode == "refused"
    assert "enabled is false" in records[0].note


async def test_apply_runs_ssh_when_enabled(raw_config, monkeypatch):
    raw_config["remediation"]["enabled"] = True
    cfg = parse_config(raw_config)
    inv = Inventory(cfg)
    calls = []

    class FakeProc:
        returncode = 0

        async def communicate(self):
            return b"done", None

    async def fake_exec(*argv, **kw):
        calls.append(argv)
        return FakeProc()

    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)
    actions = plan_remediation(inv, [_finding("dns-01", "ntp.offset")])
    records = await RemediationExecutor(inv, cfg.remediation).execute(actions, apply=True)
    assert records[0].mode == "applied"
    argv = calls[0]
    assert argv[0] == "ssh"
    assert "netops@192.0.2.10" in argv
    assert argv[-1] == "sudo chronyc makestep && chronyc tracking"
