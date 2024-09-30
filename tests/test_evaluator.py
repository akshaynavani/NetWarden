from netwarden.config import Thresholds
from netwarden.evaluator import evaluate, grade
from netwarden.models import ProbeResult, ProbeStatus, Severity

T = Thresholds()


def _by_check(findings):
    return {f.check: f for f in findings}


def test_grade_boundaries():
    assert grade(10, 50, 90) == Severity.OK
    assert grade(50, 50, 90) == Severity.WARNING
    assert grade(95, 50, 90) == Severity.CRITICAL


def test_unreachable_probe_is_critical():
    r = ProbeResult(host="h", probe="ntp", status=ProbeStatus.UNREACHABLE, error="timeout")
    (f,) = evaluate(r, T)
    assert f.check == "ntp.reachability"
    assert f.severity == Severity.CRITICAL


def test_skipped_probe_yields_nothing():
    r = ProbeResult(host="h", probe="dns", status=ProbeStatus.SKIPPED)
    assert evaluate(r, T) == []


def test_ntp_offset_is_graded_by_absolute_value():
    r = ProbeResult(
        host="h", probe="ntp", status=ProbeStatus.OK, metrics={"offset_ms": -650.0, "stratum": 2}
    )
    f = _by_check(evaluate(r, T))
    assert f["ntp.offset"].severity == Severity.CRITICAL
    assert f["ntp.stratum"].severity == Severity.OK


def test_ntp_unsynchronised_stratum():
    r = ProbeResult(
        host="h", probe="ntp", status=ProbeStatus.ERROR, metrics={"offset_ms": 1.0, "stratum": 16}
    )
    assert _by_check(evaluate(r, T))["ntp.stratum"].severity == Severity.CRITICAL


def test_dns_mismatch_and_latency():
    r = ProbeResult(
        host="h",
        probe="dns",
        status=ProbeStatus.ERROR,
        metrics={
            "records": {
                "a.example/A": {
                    "ok": False,
                    "rcode": "NOERROR",
                    "answers": ["10.9.9.9"],
                    "missing": ["10.0.0.1"],
                    "latency_ms": 250,
                }
            },
            "max_latency_ms": 250,
        },
    )
    f = _by_check(evaluate(r, T))
    assert f["dns.record.a.example/A"].severity == Severity.CRITICAL
    assert f["dns.latency"].severity == Severity.WARNING


def test_snmp_interface_down_and_error_delta():
    prev = ProbeResult(
        host="sw",
        probe="snmp",
        status=ProbeStatus.OK,
        metrics={
            "uptime_seconds": 10_000,
            "interfaces": {"1": {"in_errors": 100, "out_errors": 0}},
        },
    )
    cur = ProbeResult(
        host="sw",
        probe="snmp",
        status=ProbeStatus.OK,
        metrics={
            "uptime_seconds": 10_060,
            "cpu_pct": 97.0,
            "interfaces": {
                "1": {
                    "descr": "eth1",
                    "admin_status": "up",
                    "oper_status": "down",
                    "in_errors": 1300,
                    "out_errors": 5,
                }
            },
        },
    )
    f = _by_check(evaluate(cur, T, prev))
    assert f["snmp.if_status.1"].severity == Severity.CRITICAL
    assert f["snmp.if_status.1"].context["if_descr"] == "eth1"
    assert f["snmp.if_errors.1"].value == 1205
    assert f["snmp.if_errors.1"].severity == Severity.CRITICAL
    assert f["snmp.cpu"].severity == Severity.CRITICAL
    assert f["snmp.uptime"].severity == Severity.OK


def test_snmp_reboot_detected_from_uptime_drop():
    prev = ProbeResult(host="sw", probe="snmp", status=ProbeStatus.OK, metrics={"uptime_seconds": 90_000})
    cur = ProbeResult(host="sw", probe="snmp", status=ProbeStatus.OK, metrics={"uptime_seconds": 80_000})
    assert _by_check(evaluate(cur, T, prev))["snmp.uptime"].severity == Severity.WARNING


def test_counter_wrap_is_ignored():
    prev = ProbeResult(
        host="sw", probe="snmp", status=ProbeStatus.OK,
        metrics={"interfaces": {"1": {"in_errors": 5000, "out_errors": 0}}},
    )
    cur = ProbeResult(
        host="sw", probe="snmp", status=ProbeStatus.OK,
        metrics={"interfaces": {"1": {"admin_status": "up", "oper_status": "up",
                                      "in_errors": 3, "out_errors": 0}}},
    )
    assert "snmp.if_errors.1" not in _by_check(evaluate(cur, T, prev))


def test_tcp_closed_port_and_dhcp_pool():
    tcp = ProbeResult(
        host="h", probe="tcp", status=ProbeStatus.ERROR,
        metrics={"ports": {"22": {"open": True, "latency_ms": 5}, "53": {"open": False, "error": "refused"}}},
    )
    f = _by_check(evaluate(tcp, T))
    assert f["tcp.port.22"].severity == Severity.OK
    assert f["tcp.port.53"].severity == Severity.CRITICAL

    dhcp = ProbeResult(
        host="h", probe="dhcp", status=ProbeStatus.OK,
        metrics={"pool_utilisation_pct": 85.0, "leases_active": 170, "pool_size": 200},
    )
    assert _by_check(evaluate(dhcp, T))["dhcp.pool"].severity == Severity.WARNING
