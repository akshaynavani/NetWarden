"""Probe base class.

A probe checks one aspect of one host and returns a :class:`ProbeResult`. Probes never raise:
timeouts and exceptions are converted into UNREACHABLE / ERROR results so a single bad host
cannot break a poll cycle.
"""

from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from typing import Any

from netwarden.config import Host, NetWardenConfig
from netwarden.models import ProbeResult, ProbeStatus

log = logging.getLogger(__name__)


class ProbeUnreachable(Exception):
    """The target did not answer at all."""


class Probe(ABC):
    name: str = "base"

    def __init__(self, config: NetWardenConfig) -> None:
        self.config = config

    def applies_to(self, host: Host) -> bool:
        return self.name in host.checks.enabled()

    @abstractmethod
    async def collect(self, host: Host) -> tuple[ProbeStatus, dict[str, Any]]:
        """Gather metrics. May raise; :meth:`run` handles errors."""

    async def run(self, host: Host, timeout: float | None = None) -> ProbeResult:
        timeout = timeout or self.config.polling.probe_timeout_seconds
        started = time.perf_counter()
        status: ProbeStatus
        metrics: dict[str, Any] = {}
        error: str | None = None
        try:
            status, metrics = await asyncio.wait_for(self.collect(host), timeout=timeout)
        except (asyncio.TimeoutError, ProbeUnreachable) as exc:
            status = ProbeStatus.UNREACHABLE
            error = str(exc) or f"timed out after {timeout:.1f}s"
        except Exception as exc:  # noqa: BLE001 - probes must not take the poller down
            log.debug("probe %s on %s failed", self.name, host.name, exc_info=True)
            status = ProbeStatus.ERROR
            error = f"{type(exc).__name__}: {exc}"
        duration = (time.perf_counter() - started) * 1000
        return ProbeResult(
            host=host.name,
            probe=self.name,
            status=status,
            metrics=metrics,
            error=error,
            duration_ms=round(duration, 2),
        )
