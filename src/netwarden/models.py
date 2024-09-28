"""Shared result types passed between probes, evaluator, alerting and reporting."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ProbeStatus(str, Enum):
    OK = "ok"
    ERROR = "error"  # probe ran but the service answered badly
    UNREACHABLE = "unreachable"  # no answer at all / timeout
    SKIPPED = "skipped"


class Severity(str, Enum):
    OK = "ok"
    WARNING = "warning"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"ok": 0, "warning": 1, "critical": 2}[self.value]

    def __ge__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.rank >= other.rank

    def __gt__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.rank > other.rank


class ProbeResult(BaseModel):
    host: str
    probe: str
    status: ProbeStatus
    metrics: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    duration_ms: float = 0.0
    timestamp: datetime = Field(default_factory=utcnow)


class Finding(BaseModel):
    """A single evaluated condition, e.g. "ntp offset 620ms on core-sw-01"."""

    host: str
    probe: str
    check: str  # stable key, e.g. "ntp.offset" or "snmp.if_oper_status.3"
    severity: Severity
    message: str
    value: Any = None
    threshold: Any = None
    context: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=utcnow)

    @property
    def key(self) -> str:
        return f"{self.host}:{self.check}"


class PollCycle(BaseModel):
    started_at: datetime
    finished_at: datetime
    results: list[ProbeResult]
    findings: list[Finding]

    @property
    def worst(self) -> Severity:
        worst = Severity.OK
        for f in self.findings:
            if f.severity > worst:
                worst = f.severity
        return worst
