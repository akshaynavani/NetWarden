"""NTP drift probe: measures clock offset of a host relative to the NetWarden server."""

from __future__ import annotations

import asyncio
from typing import Any

import ntplib

from netwarden.config import Host
from netwarden.models import ProbeStatus
from netwarden.probes.base import Probe, ProbeUnreachable


class NtpProbe(Probe):
    name = "ntp"

    def _query(self, address: str, version: int, port: int, timeout: float) -> Any:
        client = ntplib.NTPClient()
        try:
            return client.request(address, version=version, port=port, timeout=timeout)
        except ntplib.NTPException as exc:
            raise ProbeUnreachable(f"no NTP response: {exc}") from exc

    async def collect(self, host: Host) -> tuple[ProbeStatus, dict[str, Any]]:
        check = host.checks.ntp
        assert check is not None
        timeout = max(1.0, self.config.polling.probe_timeout_seconds / 2)
        resp = await asyncio.to_thread(
            self._query, host.address, check.version, check.port, timeout
        )
        metrics = {
            "offset_ms": round(resp.offset * 1000, 3),
            "delay_ms": round(resp.delay * 1000, 3),
            "stratum": resp.stratum,
            "ref_id": ntplib.ref_id_to_text(resp.ref_id, resp.stratum),
            "leap": ntplib.leap_to_text(resp.leap),
        }
        # Stratum 16 means "unsynchronised"; leap indicator 3 means alarm.
        status = ProbeStatus.ERROR if resp.stratum >= 16 or resp.leap == 3 else ProbeStatus.OK
        return status, metrics
