"""Concurrent poller: runs every applicable probe against every selected host."""

from __future__ import annotations

import asyncio
import logging

from netwarden.config import Host
from netwarden.inventory import Inventory
from netwarden.models import ProbeResult
from netwarden.probes import Probe, build_probes

log = logging.getLogger(__name__)


class Poller:
    def __init__(self, inventory: Inventory, probes: list[Probe] | None = None) -> None:
        self.inventory = inventory
        self.config = inventory.config
        self.probes = probes if probes is not None else build_probes(self.config)
        self._sem = asyncio.Semaphore(self.config.polling.concurrency)

    async def _run_one(self, probe: Probe, host: Host) -> ProbeResult:
        # Defence in depth: refuse anything that isn't in the inventory.
        self.inventory.require_address(host.address)
        async with self._sem:
            result = await probe.run(host)
        log.debug("%s/%s -> %s", host.name, probe.name, result.status.value)
        return result

    async def poll(self, hosts: list[Host] | None = None) -> list[ProbeResult]:
        hosts = hosts if hosts is not None else list(self.inventory)
        tasks = [
            self._run_one(probe, host)
            for host in hosts
            for probe in self.probes
            if probe.applies_to(host)
        ]
        if not tasks:
            return []
        return list(await asyncio.gather(*tasks))
