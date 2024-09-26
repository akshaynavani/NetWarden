"""TCP service reachability probe."""

from __future__ import annotations

import asyncio
import time
from typing import Any

from netwarden.config import Host
from netwarden.models import ProbeStatus
from netwarden.probes.base import Probe


class TcpProbe(Probe):
    name = "tcp"

    async def _connect(self, address: str, port: int, timeout: float) -> dict[str, Any]:
        started = time.perf_counter()
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(address, port), timeout=timeout
            )
        except (OSError, asyncio.TimeoutError) as exc:
            return {"open": False, "error": str(exc) or type(exc).__name__}
        latency = (time.perf_counter() - started) * 1000
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return {"open": True, "latency_ms": round(latency, 2)}

    async def collect(self, host: Host) -> tuple[ProbeStatus, dict[str, Any]]:
        check = host.checks.tcp
        assert check is not None
        per_port_timeout = max(1.0, self.config.polling.probe_timeout_seconds / 2)
        results = await asyncio.gather(
            *(self._connect(host.address, p, per_port_timeout) for p in check.ports)
        )
        ports = {str(p): r for p, r in zip(check.ports, results)}
        if not ports:
            return ProbeStatus.SKIPPED, {}
        open_count = sum(1 for r in ports.values() if r["open"])
        if open_count == 0:
            status = ProbeStatus.UNREACHABLE
        elif open_count < len(ports):
            status = ProbeStatus.ERROR
        else:
            status = ProbeStatus.OK
        return status, {"ports": ports}
