"""DHCP probe.

Two independent mechanisms, both optional per host:

1. **Lease-file utilisation** -- parse an ISC dhcpd or dnsmasq lease file that is readable from
   the NetWarden host (run NetWarden on the DHCP server, or sync the file) and compute how full
   the pool is.
2. **Active DISCOVER** -- broadcast a DHCPDISCOVER and wait for an OFFER whose server identifier
   matches the configured host. Needs root (binds UDP/68) and is therefore off by default.
"""

from __future__ import annotations

import asyncio
import random
import re
import socket
import struct
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from netwarden.config import Host
from netwarden.models import ProbeStatus
from netwarden.probes.base import Probe, ProbeUnreachable

# --------------------------------------------------------------------------- lease files

_ISC_LEASE_RE = re.compile(r"lease\s+(\d{1,3}(?:\.\d{1,3}){3})\s*\{(.*?)\}", re.S)
_ISC_ENDS_RE = re.compile(r"ends\s+(?:\d\s+)?(never|\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})")
_ISC_STATE_RE = re.compile(r"(?<!next )binding\s+state\s+(\w+)")


@dataclass
class LeaseStats:
    active: int
    expired: int
    total_seen: int


def parse_isc_leases(text: str, now: datetime | None = None) -> LeaseStats:
    """Parse ISC dhcpd.leases. Later declarations for the same IP supersede earlier ones."""
    now = now or datetime.now(timezone.utc)
    latest: dict[str, bool] = {}
    for ip, body in _ISC_LEASE_RE.findall(text):
        state_match = _ISC_STATE_RE.search(body)
        state = state_match.group(1) if state_match else None
        ends_match = _ISC_ENDS_RE.search(body)
        if ends_match is None or ends_match.group(1) == "never":
            not_expired = True
        else:
            ends = datetime.strptime(ends_match.group(1), "%Y/%m/%d %H:%M:%S").replace(
                tzinfo=timezone.utc
            )
            not_expired = ends > now
        active = not_expired and (state is None or state == "active")
        latest[ip] = active
    active_count = sum(latest.values())
    return LeaseStats(
        active=active_count, expired=len(latest) - active_count, total_seen=len(latest)
    )


def parse_dnsmasq_leases(text: str, now: float | None = None) -> LeaseStats:
    """Parse dnsmasq leases: ``<expiry-epoch> <mac> <ip> <hostname> <client-id>``."""
    now = now if now is not None else time.time()
    latest: dict[str, bool] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3 or not parts[0].isdigit():
            continue
        expiry, ip = int(parts[0]), parts[2]
        latest[ip] = expiry == 0 or expiry > now
    active = sum(latest.values())
    return LeaseStats(active=active, expired=len(latest) - active, total_seen=len(latest))


# --------------------------------------------------------------------------- DHCP packets

DHCP_MAGIC_COOKIE = b"\x63\x82\x53\x63"
DHCPDISCOVER = 1
DHCPOFFER = 2
OPT_MSG_TYPE = 53
OPT_SERVER_ID = 54
OPT_PARAM_REQ = 55
OPT_LEASE_TIME = 51
OPT_SUBNET = 1
OPT_ROUTER = 3
OPT_DNS = 6
OPT_END = 255
OPT_PAD = 0


def random_mac() -> bytes:
    # Locally administered, unicast.
    first = (random.randint(0, 255) & 0xFC) | 0x02
    return bytes([first] + [random.randint(0, 255) for _ in range(5)])


def build_discover(xid: int, mac: bytes) -> bytes:
    if len(mac) != 6:
        raise ValueError("mac must be 6 bytes")
    header = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        1,  # op: BOOTREQUEST
        1,  # htype: ethernet
        6,  # hlen
        0,  # hops
        xid,
        0,  # secs
        0x8000,  # flags: broadcast reply
        b"\x00" * 4,
        b"\x00" * 4,
        b"\x00" * 4,
        b"\x00" * 4,
        mac + b"\x00" * 10,
        b"\x00" * 64,
        b"\x00" * 128,
    )
    options = bytes(
        [OPT_MSG_TYPE, 1, DHCPDISCOVER]
        + [OPT_PARAM_REQ, 5, OPT_SUBNET, OPT_ROUTER, OPT_DNS, OPT_LEASE_TIME, OPT_SERVER_ID]
        + [OPT_END]
    )
    return header + DHCP_MAGIC_COOKIE + options


def parse_options(data: bytes) -> dict[int, bytes]:
    opts: dict[int, bytes] = {}
    i = 0
    while i < len(data):
        code = data[i]
        if code == OPT_END:
            break
        if code == OPT_PAD:
            i += 1
            continue
        if i + 1 >= len(data):
            break
        length = data[i + 1]
        opts[code] = data[i + 2 : i + 2 + length]
        i += 2 + length
    return opts


def parse_offer(packet: bytes, xid: int) -> dict[str, Any] | None:
    """Return OFFER details if ``packet`` is a DHCPOFFER for ``xid``; otherwise None."""
    if len(packet) < 240 or packet[0] != 2:
        return None
    (pkt_xid,) = struct.unpack("!I", packet[4:8])
    if pkt_xid != xid or packet[236:240] != DHCP_MAGIC_COOKIE:
        return None
    opts = parse_options(packet[240:])
    if opts.get(OPT_MSG_TYPE) != bytes([DHCPOFFER]):
        return None
    offer: dict[str, Any] = {"offered_ip": socket.inet_ntoa(packet[16:20])}
    if OPT_SERVER_ID in opts and len(opts[OPT_SERVER_ID]) == 4:
        offer["server_id"] = socket.inet_ntoa(opts[OPT_SERVER_ID])
    if OPT_LEASE_TIME in opts and len(opts[OPT_LEASE_TIME]) == 4:
        offer["lease_seconds"] = struct.unpack("!I", opts[OPT_LEASE_TIME])[0]
    if OPT_ROUTER in opts and len(opts[OPT_ROUTER]) >= 4:
        offer["router"] = socket.inet_ntoa(opts[OPT_ROUTER][:4])
    return offer


def discover_once(server_ip: str, interface: str | None, timeout: float) -> dict[str, Any]:
    """Blocking DISCOVER/OFFER exchange. Only OFFERs from ``server_ip`` are accepted."""
    xid = random.getrandbits(32)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if interface and hasattr(socket, "SO_BINDTODEVICE"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode())
        try:
            sock.bind(("0.0.0.0", 68))
        except PermissionError as exc:
            raise PermissionError(
                "active DHCP probe needs root or CAP_NET_BIND_SERVICE to bind UDP port 68"
            ) from exc
        started = time.perf_counter()
        sock.sendto(build_discover(xid, random_mac()), ("255.255.255.255", 67))
        deadline = time.monotonic() + timeout
        while (remaining := deadline - time.monotonic()) > 0:
            sock.settimeout(remaining)
            try:
                packet, (src, _) = sock.recvfrom(4096)
            except socket.timeout:
                break
            offer = parse_offer(packet, xid)
            if offer is None:
                continue
            if offer.get("server_id", src) != server_ip and src != server_ip:
                continue  # some other DHCP server answered; not ours to judge
            offer["response_ms"] = round((time.perf_counter() - started) * 1000, 2)
            return offer
    finally:
        sock.close()
    raise ProbeUnreachable(f"no DHCPOFFER from {server_ip} within {timeout:.1f}s")


# --------------------------------------------------------------------------- probe


class DhcpProbe(Probe):
    name = "dhcp"

    async def collect(self, host: Host) -> tuple[ProbeStatus, dict[str, Any]]:
        check = host.checks.dhcp
        assert check is not None
        metrics: dict[str, Any] = {}
        status = ProbeStatus.OK

        if check.lease_file is not None:
            path = Path(check.lease_file)
            text = await asyncio.to_thread(path.read_text, errors="replace")
            parser = parse_isc_leases if check.lease_format == "isc" else parse_dnsmasq_leases
            stats = parser(text)
            pool = check.pool_size or 1
            metrics["leases_active"] = stats.active
            metrics["leases_expired"] = stats.expired
            metrics["pool_size"] = pool
            metrics["pool_utilisation_pct"] = round(100 * stats.active / pool, 1)

        if check.active_probe:
            timeout = max(1.0, self.config.polling.probe_timeout_seconds - 1)
            try:
                metrics["offer"] = await asyncio.to_thread(
                    discover_once, host.address, check.interface, timeout
                )
            except ProbeUnreachable as exc:
                metrics["offer"] = None
                metrics["offer_error"] = str(exc)
                status = ProbeStatus.UNREACHABLE if check.lease_file is None else ProbeStatus.ERROR
        return status, metrics
