"""Alert lifecycle: pending -> firing -> resolved, with flap suppression and re-notification."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from enum import Enum

from netwarden.config import AlertingConfig
from netwarden.models import Finding, Severity
from netwarden.state import AlertRow, StateStore


class EventKind(str, Enum):
    FIRED = "fired"
    ESCALATED = "escalated"
    REMINDER = "reminder"
    RESOLVED = "resolved"


@dataclass
class AlertEvent:
    kind: EventKind
    finding: Finding
    alert: AlertRow

    @property
    def severity(self) -> Severity:
        return self.finding.severity if self.kind != EventKind.RESOLVED else self.alert.severity

    def summary(self) -> str:
        tag = self.kind.value.upper()
        if self.kind == EventKind.RESOLVED:
            return f"[{tag}] {self.alert.host} {self.alert.check_name}: {self.finding.message}"
        return (
            f"[{tag}/{self.finding.severity.value.upper()}] {self.finding.host} "
            f"{self.finding.check}: {self.finding.message}"
        )


class AlertManager:
    def __init__(self, store: StateStore, config: AlertingConfig) -> None:
        self.store = store
        self.config = config

    def process(self, findings: list[Finding]) -> list[AlertEvent]:
        events: list[AlertEvent] = []
        for finding in findings:
            event = self._process_one(finding)
            if event is not None:
                events.append(event)
        return events

    def _process_one(self, f: Finding) -> AlertEvent | None:
        existing = self.store.get_alert(f.key)
        now = f.timestamp

        if f.severity == Severity.OK:
            if existing is None or existing.state == "resolved":
                return None
            was_firing = existing.state == "firing"
            existing.state = "resolved"
            existing.consecutive = 0
            existing.last_seen = now
            existing.message = f.message
            self.store.upsert_alert(existing)
            if was_firing and self.config.notify_on_recovery:
                return AlertEvent(EventKind.RESOLVED, f, existing)
            return None

        active = existing is not None and existing.state != "resolved"
        consecutive = existing.consecutive + 1 if active and existing else 1
        alert = AlertRow(
            key=f.key,
            host=f.host,
            probe=f.probe,
            check_name=f.check,
            severity=f.severity,
            message=f.message,
            state="pending",
            consecutive=consecutive,
            first_seen=existing.first_seen if active and existing else now,
            last_seen=now,
            last_notified=existing.last_notified if active and existing else None,
        )

        kind: EventKind | None = None
        if consecutive >= self.config.consecutive_failures:
            alert.state = "firing"
            if not active or existing is None or existing.state != "firing":
                kind = EventKind.FIRED
            elif f.severity > existing.severity:
                kind = EventKind.ESCALATED
            elif self._reminder_due(alert):
                kind = EventKind.REMINDER

        if kind is not None:
            alert.last_notified = now
        self.store.upsert_alert(alert)
        return AlertEvent(kind, f, alert) if kind else None

    def _reminder_due(self, alert: AlertRow) -> bool:
        if self.config.renotify_minutes <= 0 or alert.last_notified is None:
            return False
        return alert.last_seen - alert.last_notified >= timedelta(
            minutes=self.config.renotify_minutes
        )
