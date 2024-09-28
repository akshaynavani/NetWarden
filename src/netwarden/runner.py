"""Ties poller, evaluator, state, alerting and reporting into poll cycles."""

from __future__ import annotations

import asyncio
import logging
import signal
from typing import Any

from netwarden.alerts import AlertEvent, AlertManager
from netwarden.config import Host
from netwarden.evaluator import evaluate
from netwarden.inventory import Inventory
from netwarden.models import Finding, PollCycle, ProbeResult, utcnow
from netwarden.notifiers import Notifier, build_notifiers, dispatch
from netwarden.poller import Poller
from netwarden.reports import build_report, write_reports
from netwarden.state import StateStore

log = logging.getLogger(__name__)


class Runner:
    def __init__(
        self,
        inventory: Inventory,
        store: StateStore | None = None,
        poller: Poller | None = None,
        notifiers: list[Notifier] | None = None,
    ) -> None:
        self.inventory = inventory
        self.config = inventory.config
        self.store = store or StateStore(self.config.storage.sqlite_path)
        self.poller = poller or Poller(inventory)
        self.alerts = AlertManager(self.store, self.config.alerting)
        self.notifiers = (
            notifiers if notifiers is not None else build_notifiers(self.config.alerting.notifiers)
        )

    def evaluate_results(
        self, results: list[ProbeResult], use_history: bool = True
    ) -> list[Finding]:
        findings: list[Finding] = []
        for r in results:
            host = self.inventory.get(r.host)
            previous = self.store.latest_result(r.host, r.probe) if use_history else None
            findings.extend(evaluate(r, self.config.thresholds_for(host), previous))
        return findings

    async def run_cycle(
        self, hosts: list[Host] | None = None, write_report: bool = True
    ) -> tuple[PollCycle, list[AlertEvent], dict[str, Any]]:
        started = utcnow()
        results = await self.poller.poll(hosts)
        findings = self.evaluate_results(results)  # must run before saving (uses previous)
        self.store.save_results(results)
        events = self.alerts.process(findings)
        await dispatch(self.notifiers, events)
        cycle = PollCycle(
            started_at=started, finished_at=utcnow(), results=results, findings=findings
        )
        report = build_report(cycle, self.store.open_alerts())
        if write_report:
            write_reports(report, self.config.storage.report_dir)
        log.info(
            "cycle done: %d results, %d findings, %d alert events, overall=%s",
            len(results),
            len(findings),
            len(events),
            cycle.worst.value,
        )
        return cycle, events, report

    async def run_forever(self, hosts: list[Host] | None = None) -> None:
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, stop.set)
            except NotImplementedError:  # pragma: no cover - Windows
                pass

        interval = self.config.polling.interval_seconds
        cycles = 0
        while not stop.is_set():
            try:
                await self.run_cycle(hosts)
            except Exception:  # noqa: BLE001 - keep the daemon alive
                log.exception("poll cycle failed")
            cycles += 1
            if cycles % 60 == 0:
                pruned = self.store.prune(self.config.storage.history_days)
                log.info("pruned %d old probe results", pruned)
            try:
                await asyncio.wait_for(stop.wait(), timeout=interval)
            except asyncio.TimeoutError:
                pass
        log.info("shutting down")
        self.store.close()
