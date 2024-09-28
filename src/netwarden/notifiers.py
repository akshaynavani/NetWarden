"""Alert delivery channels."""

from __future__ import annotations

import asyncio
import json
import logging
import smtplib
from abc import ABC, abstractmethod
from email.message import EmailMessage
from pathlib import Path

import httpx
from rich.console import Console

from netwarden.alerts import AlertEvent, EventKind
from netwarden.config import NotifierConfig
from netwarden.models import Severity

log = logging.getLogger(__name__)


class Notifier(ABC):
    def __init__(self, cfg: NotifierConfig) -> None:
        self.cfg = cfg
        self.min_severity = Severity(cfg.min_severity)

    def wants(self, event: AlertEvent) -> bool:
        return event.severity >= self.min_severity

    @abstractmethod
    async def send(self, events: list[AlertEvent]) -> None: ...


class ConsoleNotifier(Notifier):
    STYLES = {Severity.CRITICAL: "bold red", Severity.WARNING: "yellow", Severity.OK: "green"}

    def __init__(self, cfg: NotifierConfig, console: Console | None = None) -> None:
        super().__init__(cfg)
        self.console = console or Console(stderr=True)

    async def send(self, events: list[AlertEvent]) -> None:
        for e in events:
            style = "green" if e.kind == EventKind.RESOLVED else self.STYLES[e.severity]
            self.console.print(e.summary(), style=style)


def event_to_dict(e: AlertEvent) -> dict:
    return {
        "event": e.kind.value,
        "severity": e.severity.value,
        "host": e.finding.host,
        "probe": e.finding.probe,
        "check": e.finding.check,
        "message": e.finding.message,
        "value": e.finding.value,
        "threshold": e.finding.threshold,
        "first_seen": e.alert.first_seen.isoformat(),
        "timestamp": e.finding.timestamp.isoformat(),
    }


class JsonlNotifier(Notifier):
    async def send(self, events: list[AlertEvent]) -> None:
        path = Path(self.cfg.path)  # type: ignore[arg-type]
        path.parent.mkdir(parents=True, exist_ok=True)
        lines = "".join(json.dumps(event_to_dict(e), default=str) + "\n" for e in events)
        await asyncio.to_thread(self._append, path, lines)

    @staticmethod
    def _append(path: Path, text: str) -> None:
        with path.open("a") as fh:
            fh.write(text)


class WebhookNotifier(Notifier):
    """POSTs a Slack-compatible payload (``text``) plus structured ``events``."""

    async def send(self, events: list[AlertEvent]) -> None:
        payload = {
            "text": "\n".join(e.summary() for e in events),
            "events": [event_to_dict(e) for e in events],
        }
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(self.cfg.url, json=payload)  # type: ignore[arg-type]
            resp.raise_for_status()


class EmailNotifier(Notifier):
    async def send(self, events: list[AlertEvent]) -> None:
        msg = EmailMessage()
        worst = max((e.severity for e in events), key=lambda s: s.rank)
        msg["Subject"] = f"[NetWarden] {len(events)} alert event(s), worst: {worst.value}"
        msg["From"] = self.cfg.sender
        msg["To"] = ", ".join(self.cfg.recipients)
        msg.set_content("\n".join(e.summary() for e in events))
        await asyncio.to_thread(self._deliver, msg)

    def _deliver(self, msg: EmailMessage) -> None:
        with smtplib.SMTP(self.cfg.smtp_host, self.cfg.smtp_port, timeout=15) as smtp:  # type: ignore[arg-type]
            smtp.starttls()
            if self.cfg.smtp_user and self.cfg.smtp_password:
                smtp.login(self.cfg.smtp_user, self.cfg.smtp_password)
            smtp.send_message(msg)


NOTIFIER_TYPES: dict[str, type[Notifier]] = {
    "console": ConsoleNotifier,
    "jsonl": JsonlNotifier,
    "webhook": WebhookNotifier,
    "email": EmailNotifier,
}


def build_notifiers(configs: list[NotifierConfig]) -> list[Notifier]:
    notifiers: list[Notifier] = []
    for cfg in configs:
        if cfg.type == "webhook" and not cfg.url:
            continue  # webhook URL left blank via ${VAR:-}: treat as disabled
        notifiers.append(NOTIFIER_TYPES[cfg.type](cfg))
    return notifiers


async def dispatch(notifiers: list[Notifier], events: list[AlertEvent]) -> None:
    """Fan events out to every notifier; one failing channel never blocks the others."""
    if not events:
        return

    async def _send(n: Notifier) -> None:
        wanted = [e for e in events if n.wants(e)]
        if not wanted:
            return
        try:
            await n.send(wanted)
        except Exception:  # noqa: BLE001
            log.exception("notifier %s failed", n.cfg.type)

    await asyncio.gather(*(_send(n) for n in notifiers))
