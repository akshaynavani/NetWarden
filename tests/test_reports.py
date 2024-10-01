import json
from datetime import timedelta

from netwarden.models import Finding, PollCycle, ProbeResult, ProbeStatus, Severity, utcnow
from netwarden.reports import build_report, render_json, render_markdown, write_reports


def _cycle():
    now = utcnow()
    results = [
        ProbeResult(host="dns-01", probe="ntp", status=ProbeStatus.OK, metrics={"offset_ms": 700}),
        ProbeResult(host="sw-01", probe="snmp", status=ProbeStatus.OK, metrics={"cpu_pct": 10}),
    ]
    findings = [
        Finding(host="dns-01", probe="ntp", check="ntp.offset", severity=Severity.CRITICAL,
                message="clock offset +700.0ms", value=700),
        Finding(host="sw-01", probe="snmp", check="snmp.cpu", severity=Severity.OK,
                message="CPU load 10%"),
    ]
    return PollCycle(started_at=now - timedelta(seconds=3), finished_at=now,
                     results=results, findings=findings)


def test_build_report_summarises_hosts():
    rep = build_report(_cycle())
    assert rep["overall"] == "critical"
    assert rep["host_counts"] == {"ok": 1, "warning": 0, "critical": 1}
    assert rep["hosts"]["dns-01"]["status"] == "critical"
    assert rep["hosts"]["dns-01"]["findings"][0]["check"] == "ntp.offset"
    assert rep["hosts"]["sw-01"]["findings"] == []
    json.loads(render_json(rep))


def test_markdown_lists_findings():
    md = render_markdown(build_report(_cycle()))
    assert "Overall: **CRITICAL**" in md
    assert "| CRITICAL | dns-01 | `ntp.offset` |" in md


def test_write_reports(tmp_path):
    paths = write_reports(build_report(_cycle()), tmp_path)
    assert all(p.exists() for p in paths)
    assert (tmp_path / "latest.md").exists()
