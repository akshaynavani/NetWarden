"""Probe registry."""

from __future__ import annotations

from netwarden.config import NetWardenConfig
from netwarden.probes.base import Probe, ProbeUnreachable
from netwarden.probes.dhcp import DhcpProbe
from netwarden.probes.dns import DnsProbe
from netwarden.probes.ntp import NtpProbe
from netwarden.probes.snmp import SnmpProbe
from netwarden.probes.tcp import TcpProbe

PROBE_CLASSES: dict[str, type[Probe]] = {
    cls.name: cls for cls in (SnmpProbe, DnsProbe, DhcpProbe, NtpProbe, TcpProbe)
}


def build_probes(config: NetWardenConfig, only: list[str] | None = None) -> list[Probe]:
    names = only or list(PROBE_CLASSES)
    unknown = set(names) - set(PROBE_CLASSES)
    if unknown:
        raise ValueError(f"unknown probes: {sorted(unknown)}")
    return [PROBE_CLASSES[n](config) for n in names]


__all__ = ["Probe", "ProbeUnreachable", "PROBE_CLASSES", "build_probes"]
