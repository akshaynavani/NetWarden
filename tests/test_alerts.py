from datetime import datetime, timedelta, timezone

from netwarden.alerts import AlertManager, EventKind
from netwarden.config import AlertingConfig
from netwarden.models import Finding, Severity
from netwarden.state import StateStore

T0 = datetime(2026, 10, 8, 12, 0, tzinfo=timezone.utc)


def _f(sev: Severity, minutes: int = 0) -> Finding:
    return Finding(
        host="h1",
        probe="ntp",
        check="ntp.offset",
        severity=sev,
        message=f"offset {sev.value}",
        timestamp=T0 + timedelta(minutes=minutes),
    )


def _mgr(**kw) -> AlertManager:
    return AlertManager(StateStore(":memory:"), AlertingConfig(notifiers=[], **kw))


def test_single_failure_is_suppressed_until_threshold():
    mgr = _mgr(consecutive_failures=2)
    assert mgr.process([_f(Severity.WARNING, 0)]) == []
    (event,) = mgr.process([_f(Severity.WARNING, 1)])
    assert event.kind == EventKind.FIRED
    assert mgr.store.open_alerts()[0].key == "h1:ntp.offset"


def test_flap_resets_counter():
    mgr = _mgr(consecutive_failures=2)
    mgr.process([_f(Severity.WARNING, 0)])
    assert mgr.process([_f(Severity.OK, 1)]) == []  # pending alert resolves silently
    assert mgr.process([_f(Severity.WARNING, 2)]) == []


def test_escalation_reminder_and_recovery():
    mgr = _mgr(consecutive_failures=1, renotify_minutes=30)
    assert mgr.process([_f(Severity.WARNING, 0)])[0].kind == EventKind.FIRED
    assert mgr.process([_f(Severity.WARNING, 5)]) == []
    assert mgr.process([_f(Severity.CRITICAL, 10)])[0].kind == EventKind.ESCALATED
    assert mgr.process([_f(Severity.CRITICAL, 20)]) == []
    assert mgr.process([_f(Severity.CRITICAL, 41)])[0].kind == EventKind.REMINDER
    (recovered,) = mgr.process([_f(Severity.OK, 50)])
    assert recovered.kind == EventKind.RESOLVED
    assert recovered.severity == Severity.CRITICAL
    assert mgr.store.open_alerts() == []


def test_recovery_notification_can_be_disabled():
    mgr = _mgr(consecutive_failures=1, notify_on_recovery=False)
    mgr.process([_f(Severity.CRITICAL, 0)])
    assert mgr.process([_f(Severity.OK, 1)]) == []
