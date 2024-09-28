"""Remediation action catalogue.

Each action knows which findings it can address and how to render the remote shell commands.
Every parameter that ends up in a command (service / interface names) must come from the host's
own allowlist in config and is validated + shell-quoted.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

from netwarden.config import Host
from netwarden.models import Finding, Severity

SAFE_NAME = re.compile(r"^[A-Za-z0-9@._:-]+$")

SERVICE_FAMILIES: dict[str, set[str]] = {
    "dns": {"named", "bind9", "unbound", "dnsmasq", "systemd-resolved", "pdns-recursor"},
    "dhcp": {"isc-dhcp-server", "dhcpd", "kea-dhcp4-server", "dnsmasq"},
    "ntp": {"chrony", "chronyd", "ntp", "ntpd", "systemd-timesyncd"},
    "snmp": {"snmpd"},
}


class UnsafeParameter(ValueError):
    pass


def safe(name: str) -> str:
    if not SAFE_NAME.fullmatch(name):
        raise UnsafeParameter(f"refusing unsafe parameter {name!r}")
    return shlex.quote(name)


@dataclass(frozen=True)
class PlannedAction:
    host: str
    action: str
    reason: str  # finding key that triggered it
    summary: str
    commands: tuple[str, ...]
    params: dict[str, str] = field(default_factory=dict, hash=False, compare=False)

    @property
    def dedupe_key(self) -> tuple[str, str, tuple[str, ...]]:
        return (self.host, self.action, self.commands)


def _service_for(host: Host, family: str) -> str | None:
    for svc in host.remediation.services:
        if svc in SERVICE_FAMILIES[family]:
            return svc
    return None


def _restart(host: Host, family: str, finding: Finding) -> PlannedAction | None:
    svc = _service_for(host, family)
    if svc is None:
        return None
    return PlannedAction(
        host=host.name,
        action="restart_service",
        reason=finding.key,
        summary=f"restart {svc} on {host.name} ({finding.message})",
        commands=(
            f"sudo systemctl restart {safe(svc)}",
            f"systemctl is-active --quiet {safe(svc)}",
        ),
        params={"service": svc},
    )


def plan_restart_service(host: Host, f: Finding) -> PlannedAction | None:
    if f.severity != Severity.CRITICAL:
        return None
    if f.check.startswith("dns.record.") or f.check == "dns.reachability":
        return _restart(host, "dns", f)
    if f.check in ("dhcp.offer", "dhcp.reachability"):
        return _restart(host, "dhcp", f)
    if f.check == "ntp.reachability" or (f.check == "ntp.stratum" and (f.value or 0) >= 16):
        return _restart(host, "ntp", f)
    return None


def plan_flush_dns_cache(host: Host, f: Finding) -> PlannedAction | None:
    if not f.check.startswith("dns.record.") or f.severity != Severity.CRITICAL:
        return None
    svc = _service_for(host, "dns")
    if svc in ("named", "bind9"):
        cmd = "sudo rndc flush"
    elif svc == "unbound":
        cmd = "sudo unbound-control flush_zone ."
    elif svc == "pdns-recursor":
        cmd = "sudo rec_control wipe-cache '$'"
    else:
        cmd = "sudo resolvectl flush-caches"
    return PlannedAction(
        host=host.name,
        action="flush_dns_cache",
        reason=f.key,
        summary=f"flush DNS cache on {host.name} ({f.message})",
        commands=(cmd,),
    )


def plan_ntp_step(host: Host, f: Finding) -> PlannedAction | None:
    if f.check != "ntp.offset" or f.severity < Severity.WARNING:
        return None
    svc = _service_for(host, "ntp")
    if svc in ("chrony", "chronyd"):
        cmds: tuple[str, ...] = ("sudo chronyc makestep", "chronyc tracking")
    elif svc in ("ntp", "ntpd"):
        cmds = (f"sudo systemctl restart {safe(svc)}", "ntpq -p")
    elif svc == "systemd-timesyncd":
        cmds = ("sudo systemctl restart systemd-timesyncd", "timedatectl timesync-status")
    else:
        return None
    return PlannedAction(
        host=host.name,
        action="ntp_step",
        reason=f.key,
        summary=f"step clock on {host.name} ({f.message})",
        commands=cmds,
    )


def plan_bounce_interface(host: Host, f: Finding) -> PlannedAction | None:
    if not f.check.startswith("snmp.if_status.") or f.severity != Severity.CRITICAL:
        return None
    # The finding message begins with the ifDescr reported by SNMP.
    descr = f.message.split(" ", 1)[0]
    if descr not in host.remediation.interfaces:
        return None
    iface = safe(descr)
    return PlannedAction(
        host=host.name,
        action="bounce_interface",
        reason=f.key,
        summary=f"bounce {descr} on {host.name} ({f.message})",
        commands=(
            f"sudo ip link set dev {iface} down",
            "sleep 2",
            f"sudo ip link set dev {iface} up",
            f"ip -br link show dev {iface}",
        ),
        params={"interface": descr},
    )


def plan_restart_snmp_agent(host: Host, f: Finding) -> PlannedAction | None:
    if f.check != "snmp.reachability" or f.severity != Severity.CRITICAL:
        return None
    return _restart(host, "snmp", f)


ACTION_PLANNERS = {
    "restart_service": plan_restart_service,
    "flush_dns_cache": plan_flush_dns_cache,
    "ntp_step": plan_ntp_step,
    "bounce_interface": plan_bounce_interface,
    "restart_snmp_agent": plan_restart_snmp_agent,
}
