"""Turn raw probe results into graded findings using configured thresholds.

The evaluator emits OK findings as well as problems so the alert manager can detect
recoveries for every check key it has seen.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from netwarden.config import Thresholds
from netwarden.models import Finding, ProbeResult, ProbeStatus, Severity


def grade(value: float, warn: float, crit: float) -> Severity:
    if value >= crit:
        return Severity.CRITICAL
    if value >= warn:
        return Severity.WARNING
    return Severity.OK


def _finding(
    result: ProbeResult,
    check: str,
    severity: Severity,
    message: str,
    value: Any = None,
    threshold: Any = None,
) -> Finding:
    return Finding(
        host=result.host,
        probe=result.probe,
        check=check,
        severity=severity,
        message=message,
        value=value,
        threshold=threshold,
        timestamp=result.timestamp,
    )


# --------------------------------------------------------------------------- per-probe rules


def _eval_snmp(r: ProbeResult, t: Thresholds, prev: ProbeResult | None) -> list[Finding]:
    out: list[Finding] = []
    m = r.metrics
    prev_m = prev.metrics if prev and prev.status == ProbeStatus.OK else {}

    uptime = m.get("uptime_seconds")
    if uptime is not None:
        prev_uptime = prev_m.get("uptime_seconds")
        rebooted = prev_uptime is not None and uptime < prev_uptime
        if rebooted or uptime < t.min_uptime_seconds:
            out.append(
                _finding(
                    r,
                    "snmp.uptime",
                    Severity.WARNING,
                    f"device restarted recently (uptime {uptime}s)",
                    uptime,
                    t.min_uptime_seconds,
                )
            )
        else:
            out.append(_finding(r, "snmp.uptime", Severity.OK, f"uptime {uptime}s", uptime))

    cpu = m.get("cpu_pct")
    if cpu is not None:
        sev = grade(cpu, t.cpu_warn_pct, t.cpu_crit_pct)
        out.append(
            _finding(r, "snmp.cpu", sev, f"CPU load {cpu}%", cpu, t.cpu_warn_pct)
        )

    prev_ifaces = prev_m.get("interfaces", {})
    for idx, iface in (m.get("interfaces") or {}).items():
        label = iface.get("descr") or f"ifIndex {idx}"
        key = f"snmp.if_status.{idx}"
        admin, oper = iface.get("admin_status"), iface.get("oper_status")
        if admin == "up" and oper not in ("up", None):
            out.append(
                _finding(r, key, Severity.CRITICAL, f"{label} is admin-up but oper-{oper}", oper)
            )
        elif oper is None:
            out.append(_finding(r, key, Severity.WARNING, f"{label} not present on agent"))
        else:
            out.append(_finding(r, key, Severity.OK, f"{label} {admin}/{oper}", oper))

        prev_iface = prev_ifaces.get(idx, {})
        delta = _error_delta(iface, prev_iface)
        if delta is not None:
            sev = grade(delta, t.if_errors_warn, t.if_errors_crit)
            out.append(
                _finding(
                    r,
                    f"snmp.if_errors.{idx}",
                    sev,
                    f"{label} logged {delta} new errors since last poll",
                    delta,
                    t.if_errors_warn,
                )
            )
    return out


def _error_delta(cur: dict[str, Any], prev: dict[str, Any]) -> int | None:
    total = 0
    for field in ("in_errors", "out_errors"):
        c, p = cur.get(field), prev.get(field)
        if not isinstance(c, int) or not isinstance(p, int):
            return None
        # Counter32 wrap or device reset: treat as no information rather than a huge spike.
        if c < p:
            return None
        total += c - p
    return total


def _eval_dns(r: ProbeResult, t: Thresholds, _prev: ProbeResult | None) -> list[Finding]:
    out: list[Finding] = []
    for key, rec in (r.metrics.get("records") or {}).items():
        check = f"dns.record.{key}"
        if rec.get("rcode") != "NOERROR":
            out.append(_finding(r, check, Severity.CRITICAL, f"{key}: {rec.get('rcode')}"))
        elif not rec.get("answers"):
            out.append(_finding(r, check, Severity.CRITICAL, f"{key}: empty answer"))
        elif rec.get("missing"):
            out.append(
                _finding(
                    r,
                    check,
                    Severity.CRITICAL,
                    f"{key}: expected {rec['missing']} but got {rec['answers']}",
                    rec["answers"],
                    rec["missing"],
                )
            )
        else:
            out.append(_finding(r, check, Severity.OK, f"{key}: {', '.join(rec['answers'])}"))
    latency = r.metrics.get("max_latency_ms")
    if latency is not None:
        sev = grade(latency, t.dns_latency_warn_ms, t.dns_latency_crit_ms)
        out.append(
            _finding(
                r, "dns.latency", sev, f"slowest DNS answer {latency}ms", latency,
                t.dns_latency_warn_ms,
            )
        )
    return out


def _eval_dhcp(r: ProbeResult, t: Thresholds, _prev: ProbeResult | None) -> list[Finding]:
    out: list[Finding] = []
    util = r.metrics.get("pool_utilisation_pct")
    if util is not None:
        sev = grade(util, t.dhcp_pool_warn_pct, t.dhcp_pool_crit_pct)
        out.append(
            _finding(
                r,
                "dhcp.pool",
                sev,
                f"pool {util}% used ({r.metrics.get('leases_active')}/"
                f"{r.metrics.get('pool_size')})",
                util,
                t.dhcp_pool_warn_pct,
            )
        )
    if "offer" in r.metrics:
        offer = r.metrics["offer"]
        if offer is None:
            out.append(
                _finding(
                    r,
                    "dhcp.offer",
                    Severity.CRITICAL,
                    r.metrics.get("offer_error") or "no DHCPOFFER received",
                )
            )
        else:
            out.append(
                _finding(
                    r,
                    "dhcp.offer",
                    Severity.OK,
                    f"offered {offer.get('offered_ip')} in {offer.get('response_ms')}ms",
                )
            )
    return out


def _eval_ntp(r: ProbeResult, t: Thresholds, _prev: ProbeResult | None) -> list[Finding]:
    out: list[Finding] = []
    offset = r.metrics.get("offset_ms")
    if offset is not None:
        sev = grade(abs(offset), t.ntp_offset_warn_ms, t.ntp_offset_crit_ms)
        out.append(
            _finding(
                r, "ntp.offset", sev, f"clock offset {offset:+.1f}ms", offset,
                t.ntp_offset_warn_ms,
            )
        )
    stratum = r.metrics.get("stratum")
    if stratum is not None:
        if stratum >= 16:
            sev, msg = Severity.CRITICAL, "NTP server is unsynchronised (stratum 16)"
        elif stratum > t.ntp_max_stratum:
            sev, msg = Severity.WARNING, f"stratum {stratum} exceeds {t.ntp_max_stratum}"
        else:
            sev, msg = Severity.OK, f"stratum {stratum}"
        out.append(_finding(r, "ntp.stratum", sev, msg, stratum, t.ntp_max_stratum))
    return out


def _eval_tcp(r: ProbeResult, t: Thresholds, _prev: ProbeResult | None) -> list[Finding]:
    out: list[Finding] = []
    for port, info in (r.metrics.get("ports") or {}).items():
        check = f"tcp.port.{port}"
        if not info.get("open"):
            out.append(
                _finding(
                    r, check, Severity.CRITICAL, f"port {port} closed: {info.get('error')}"
                )
            )
            continue
        latency = info.get("latency_ms", 0.0)
        sev = grade(latency, t.tcp_latency_warn_ms, t.tcp_latency_crit_ms)
        out.append(
            _finding(
                r, check, sev, f"port {port} open in {latency}ms", latency,
                t.tcp_latency_warn_ms,
            )
        )
    return out


RULES: dict[str, Callable[[ProbeResult, Thresholds, ProbeResult | None], list[Finding]]] = {
    "snmp": _eval_snmp,
    "dns": _eval_dns,
    "dhcp": _eval_dhcp,
    "ntp": _eval_ntp,
    "tcp": _eval_tcp,
}


def evaluate(
    result: ProbeResult, thresholds: Thresholds, previous: ProbeResult | None = None
) -> list[Finding]:
    """Grade one probe result. ``previous`` enables counter deltas and reboot detection."""
    if result.status == ProbeStatus.SKIPPED:
        return []
    reach_key = f"{result.probe}.reachability"
    if result.status == ProbeStatus.UNREACHABLE and not result.metrics:
        return [
            _finding(
                result,
                reach_key,
                Severity.CRITICAL,
                f"{result.probe} unreachable: {result.error or 'no response'}",
            )
        ]
    if result.status == ProbeStatus.ERROR and not result.metrics:
        return [
            _finding(result, reach_key, Severity.CRITICAL, f"{result.probe} failed: {result.error}")
        ]
    findings = [_finding(result, reach_key, Severity.OK, f"{result.probe} responded")]
    findings.extend(RULES[result.probe](result, thresholds, previous))
    return findings
