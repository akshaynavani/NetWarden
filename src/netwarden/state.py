"""SQLite-backed history of probe results and alert state."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

from netwarden.models import ProbeResult, ProbeStatus, Severity

SCHEMA = """
CREATE TABLE IF NOT EXISTS probe_results (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host        TEXT NOT NULL,
    probe       TEXT NOT NULL,
    status      TEXT NOT NULL,
    metrics     TEXT NOT NULL,
    error       TEXT,
    duration_ms REAL NOT NULL,
    ts          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_results_host_probe_ts ON probe_results(host, probe, ts DESC);

CREATE TABLE IF NOT EXISTS alerts (
    key            TEXT PRIMARY KEY,
    host           TEXT NOT NULL,
    probe          TEXT NOT NULL,
    check_name     TEXT NOT NULL,
    severity       TEXT NOT NULL,
    message        TEXT NOT NULL,
    state          TEXT NOT NULL,          -- pending | firing | resolved
    consecutive    INTEGER NOT NULL DEFAULT 0,
    first_seen     TEXT NOT NULL,
    last_seen      TEXT NOT NULL,
    last_notified  TEXT
);
"""


@dataclass
class AlertRow:
    key: str
    host: str
    probe: str
    check_name: str
    severity: Severity
    message: str
    state: str
    consecutive: int
    first_seen: datetime
    last_seen: datetime
    last_notified: datetime | None


def _dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


class StateStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if str(path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)

    def close(self) -> None:
        self._conn.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._conn:
            yield self._conn

    # ------------------------------------------------------------------ results

    def save_results(self, results: list[ProbeResult]) -> None:
        with self.transaction() as conn:
            conn.executemany(
                "INSERT INTO probe_results (host, probe, status, metrics, error, duration_ms, ts)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        r.host,
                        r.probe,
                        r.status.value,
                        json.dumps(r.metrics, default=str),
                        r.error,
                        r.duration_ms,
                        r.timestamp.isoformat(),
                    )
                    for r in results
                ],
            )

    def latest_result(self, host: str, probe: str) -> ProbeResult | None:
        row = self._conn.execute(
            "SELECT * FROM probe_results WHERE host = ? AND probe = ? ORDER BY ts DESC LIMIT 1",
            (host, probe),
        ).fetchone()
        return self._row_to_result(row) if row else None

    def latest_results(self) -> list[ProbeResult]:
        rows = self._conn.execute(
            """
            SELECT p.* FROM probe_results p
            JOIN (SELECT host, probe, MAX(ts) AS ts FROM probe_results GROUP BY host, probe) l
              ON p.host = l.host AND p.probe = l.probe AND p.ts = l.ts
            ORDER BY p.host, p.probe
            """
        ).fetchall()
        return [self._row_to_result(r) for r in rows]

    def prune(self, keep_days: int) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=keep_days)).isoformat()
        with self.transaction() as conn:
            cur = conn.execute("DELETE FROM probe_results WHERE ts < ?", (cutoff,))
            conn.execute("DELETE FROM alerts WHERE state = 'resolved' AND last_seen < ?", (cutoff,))
        return cur.rowcount

    @staticmethod
    def _row_to_result(row: sqlite3.Row) -> ProbeResult:
        return ProbeResult(
            host=row["host"],
            probe=row["probe"],
            status=ProbeStatus(row["status"]),
            metrics=json.loads(row["metrics"]),
            error=row["error"],
            duration_ms=row["duration_ms"],
            timestamp=datetime.fromisoformat(row["ts"]),
        )

    # ------------------------------------------------------------------ alerts

    def get_alert(self, key: str) -> AlertRow | None:
        row = self._conn.execute("SELECT * FROM alerts WHERE key = ?", (key,)).fetchone()
        return self._row_to_alert(row) if row else None

    def upsert_alert(self, alert: AlertRow) -> None:
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO alerts (key, host, probe, check_name, severity, message, state,
                                    consecutive, first_seen, last_seen, last_notified)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    severity = excluded.severity,
                    message = excluded.message,
                    state = excluded.state,
                    consecutive = excluded.consecutive,
                    first_seen = excluded.first_seen,
                    last_seen = excluded.last_seen,
                    last_notified = excluded.last_notified
                """,
                (
                    alert.key,
                    alert.host,
                    alert.probe,
                    alert.check_name,
                    alert.severity.value,
                    alert.message,
                    alert.state,
                    alert.consecutive,
                    alert.first_seen.isoformat(),
                    alert.last_seen.isoformat(),
                    alert.last_notified.isoformat() if alert.last_notified else None,
                ),
            )

    def open_alerts(self) -> list[AlertRow]:
        rows = self._conn.execute(
            "SELECT * FROM alerts WHERE state = 'firing' ORDER BY host, check_name"
        ).fetchall()
        alerts = [self._row_to_alert(r) for r in rows]
        return sorted(alerts, key=lambda a: -a.severity.rank)

    @staticmethod
    def _row_to_alert(row: sqlite3.Row) -> AlertRow:
        return AlertRow(
            key=row["key"],
            host=row["host"],
            probe=row["probe"],
            check_name=row["check_name"],
            severity=Severity(row["severity"]),
            message=row["message"],
            state=row["state"],
            consecutive=row["consecutive"],
            first_seen=_dt(row["first_seen"]),  # type: ignore[arg-type]
            last_seen=_dt(row["last_seen"]),  # type: ignore[arg-type]
            last_notified=_dt(row["last_notified"]),
        )
