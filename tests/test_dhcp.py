import socket
import struct
from datetime import datetime, timezone

import pytest

from netwarden.probes.dhcp import (
    DHCP_MAGIC_COOKIE,
    build_discover,
    parse_dnsmasq_leases,
    parse_isc_leases,
    parse_offer,
    parse_options,
    random_mac,
)

ISC = """
# The format of this file is documented in the dhcpd.leases(5) manual page.
lease 10.0.0.100 {
  starts 4 2026/10/08 08:00:00;
  ends 4 2026/10/08 20:00:00;
  binding state active;
  next binding state free;
  hardware ethernet aa:bb:cc:00:00:01;
}
lease 10.0.0.101 {
  starts 4 2026/10/07 08:00:00;
  ends 4 2026/10/07 20:00:00;
  binding state free;
}
lease 10.0.0.102 {
  starts 4 2026/10/08 09:00:00;
  ends never;
  binding state active;
}
lease 10.0.0.101 {
  starts 4 2026/10/08 11:00:00;
  ends 4 2026/10/08 23:00:00;
  binding state active;
}
"""


def test_isc_leases_latest_declaration_wins():
    now = datetime(2026, 10, 8, 12, 0, tzinfo=timezone.utc)
    stats = parse_isc_leases(ISC, now=now)
    assert stats.total_seen == 3
    assert stats.active == 3


def test_isc_leases_expire():
    now = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)
    stats = parse_isc_leases(ISC, now=now)
    assert stats.active == 1  # only the "ends never" lease
    assert stats.expired == 2


def test_dnsmasq_leases():
    text = "2000 aa:bb 10.0.0.5 laptop *\n500 aa:cc 10.0.0.6 phone *\n0 aa:dd 10.0.0.7 printer *\n"
    stats = parse_dnsmasq_leases(text, now=1000)
    assert stats.active == 2
    assert stats.expired == 1


def test_discover_packet_layout():
    mac = random_mac()
    assert mac[0] & 0x02 and not mac[0] & 0x01  # locally administered unicast
    pkt = build_discover(0xDEADBEEF, mac)
    assert pkt[0] == 1
    assert struct.unpack("!I", pkt[4:8])[0] == 0xDEADBEEF
    assert pkt[28:34] == mac
    assert pkt[236:240] == DHCP_MAGIC_COOKIE
    assert parse_options(pkt[240:])[53] == b"\x01"


def test_build_discover_rejects_bad_mac():
    with pytest.raises(ValueError):
        build_discover(1, b"\x00\x01")


def _offer(xid: int) -> bytes:
    header = bytearray(240)
    header[0] = 2
    header[4:8] = struct.pack("!I", xid)
    header[16:20] = socket.inet_aton("10.0.0.150")
    header[236:240] = DHCP_MAGIC_COOKIE
    opts = (
        bytes([53, 1, 2])
        + bytes([54, 4]) + socket.inet_aton("10.0.0.11")
        + bytes([51, 4]) + struct.pack("!I", 3600)
        + bytes([3, 4]) + socket.inet_aton("10.0.0.1")
        + bytes([255])
    )
    return bytes(header) + opts


def test_parse_offer():
    offer = parse_offer(_offer(42), 42)
    assert offer == {
        "offered_ip": "10.0.0.150",
        "server_id": "10.0.0.11",
        "lease_seconds": 3600,
        "router": "10.0.0.1",
    }


def test_parse_offer_ignores_other_transactions():
    assert parse_offer(_offer(42), 43) is None
    assert parse_offer(b"\x02" * 10, 42) is None
