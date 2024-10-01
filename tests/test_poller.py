from typing import Any

from netwarden.config import Host
from netwarden.models import ProbeStatus, Severity
from netwarden.poller import Poller
from netwarden.probes.base import Probe, ProbeUnreachable
from netwarden.runner import Runner
from netwarden.state import StateStore


class FakeNtp(Probe):
    name = "ntp"

    async def collect(self, host: Host) -> tuple[ProbeStatus, dict[str, Any]]:
        return ProbeStatus.OK, {"offset_ms": 750.0, "stratum": 2}


class DeadTcp(Probe):
    name = "tcp"

    async def collect(self, host: Host):
        raise ProbeUnreachable("connection refused")


class Boom(Probe):
    name = "dns"

    async def collect(self, host: Host):
        raise RuntimeError("kaboom")


async def test_poller_only_runs_applicable_probes(inventory):
    poller = Poller(inventory, probes=[FakeNtp(inventory.config), DeadTcp(inventory.config)])
    results = await poller.poll()
    # sw-01 has neither ntp nor tcp configured
    assert {(r.host, r.probe) for r in results} == {("dns-01", "ntp"), ("dns-01", "tcp")}
    tcp = next(r for r in results if r.probe == "tcp")
    assert tcp.status == ProbeStatus.UNREACHABLE


async def test_probe_exceptions_become_error_results(inventory):
    poller = Poller(inventory, probes=[Boom(inventory.config)])
    (result,) = await poller.poll()
    assert result.status == ProbeStatus.ERROR
    assert "kaboom" in result.error


async def test_runner_cycle_fires_alert_after_consecutive_failures(inventory, tmp_path):
    store = StateStore(":memory:")
    poller = Poller(inventory, probes=[FakeNtp(inventory.config)])
    runner = Runner(inventory, store=store, poller=poller, notifiers=[])

    cycle, events, report = await runner.run_cycle()
    assert cycle.worst == Severity.CRITICAL
    assert events == []  # consecutive_failures = 2

    _, events, report = await runner.run_cycle()
    assert [e.finding.check for e in events] == ["ntp.offset"]
    assert report["open_alerts"][0]["host"] == "dns-01"
    assert (inventory.config.storage.report_dir / "latest.json").exists()
