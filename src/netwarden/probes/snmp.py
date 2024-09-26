"""SNMP probe (v2c / v3) built on the pysnmp 7 asyncio high-level API.

Collected metrics:
- system: sysName, sysDescr, sysUpTime (seconds)
- interfaces: ifDescr, ifAdminStatus, ifOperStatus, ifInErrors, ifOutErrors per watched ifIndex
- cpu: average hrProcessorLoad across processors (HOST-RESOURCES-MIB), when available
"""

from __future__ import annotations

from typing import Any

from netwarden.config import Host, SnmpCredentials
from netwarden.models import ProbeStatus
from netwarden.probes.base import Probe, ProbeUnreachable

SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
IF_IN_ERRORS = "1.3.6.1.2.1.2.2.1.14"
IF_OUT_ERRORS = "1.3.6.1.2.1.2.2.1.20"
HR_PROCESSOR_LOAD = "1.3.6.1.2.1.25.3.3.1.2"

IF_STATUS_NAMES = {
    1: "up",
    2: "down",
    3: "testing",
    4: "unknown",
    5: "dormant",
    6: "notPresent",
    7: "lowerLayerDown",
}


class SnmpError(Exception):
    pass


class SnmpClient:
    """Thin async wrapper around pysnmp so the probe logic stays testable."""

    def __init__(self, address: str, creds: SnmpCredentials) -> None:
        self.address = address
        self.creds = creds
        from pysnmp.hlapi.v3arch import asyncio as hl  # lazy: heavy import

        self._hl = hl
        self._engine = hl.SnmpEngine()

    def _auth(self) -> Any:
        hl = self._hl
        c = self.creds
        if c.version == "2c":
            return hl.CommunityData(c.community, mpModel=1)
        auth_map = {
            "SHA": hl.usmHMACSHAAuthProtocol,
            "SHA256": hl.usmHMAC192SHA256AuthProtocol,
            "MD5": hl.usmHMACMD5AuthProtocol,
        }
        priv_map = {
            "AES": hl.usmAesCfb128Protocol,
            "AES256": hl.usmAesCfb256Protocol,
            "DES": hl.usmDESPrivProtocol,
        }
        kwargs: dict[str, Any] = {}
        if c.auth_key:
            kwargs["authKey"] = c.auth_key
            kwargs["authProtocol"] = auth_map[c.auth_protocol or "SHA"]
        if c.priv_key:
            kwargs["privKey"] = c.priv_key
            kwargs["privProtocol"] = priv_map[c.priv_protocol or "AES"]
        return hl.UsmUserData(c.username, **kwargs)

    async def _target(self) -> Any:
        return await self._hl.UdpTransportTarget.create(
            (self.address, self.creds.port), timeout=self.creds.timeout, retries=self.creds.retries
        )

    async def get(self, *oids: str) -> dict[str, Any]:
        hl = self._hl
        err_ind, err_status, err_index, var_binds = await hl.get_cmd(
            self._engine,
            self._auth(),
            await self._target(),
            hl.ContextData(),
            *(hl.ObjectType(hl.ObjectIdentity(o)) for o in oids),
        )
        if err_ind:
            raise ProbeUnreachable(str(err_ind))
        if err_status:
            raise SnmpError(f"{err_status.prettyPrint()} at index {int(err_index)}")
        out: dict[str, Any] = {}
        for name, value in var_binds:
            out[str(name)] = None if _is_no_such(value) else _to_python(value)
        return out

    async def walk(self, oid: str, max_rows: int = 256) -> dict[str, Any]:
        hl = self._hl
        out: dict[str, Any] = {}
        async for err_ind, err_status, _, var_binds in hl.walk_cmd(
            self._engine,
            self._auth(),
            await self._target(),
            hl.ContextData(),
            hl.ObjectType(hl.ObjectIdentity(oid)),
            lexicographicMode=False,
        ):
            if err_ind:
                raise ProbeUnreachable(str(err_ind))
            if err_status:
                raise SnmpError(err_status.prettyPrint())
            for name, value in var_binds:
                out[str(name)] = _to_python(value)
            if len(out) >= max_rows:
                break
        return out

    def close(self) -> None:
        try:
            self._engine.close_dispatcher()
        except Exception:  # noqa: BLE001
            pass


def _is_no_such(value: Any) -> bool:
    return type(value).__name__ in {"NoSuchObject", "NoSuchInstance", "EndOfMibView"}


def _to_python(value: Any) -> Any:
    try:
        return int(value)
    except (TypeError, ValueError):
        return value.prettyPrint() if hasattr(value, "prettyPrint") else str(value)


def parse_interfaces(raw: dict[str, Any], indexes: list[int]) -> dict[str, dict[str, Any]]:
    interfaces: dict[str, dict[str, Any]] = {}
    for idx in indexes:
        admin = raw.get(f"{IF_ADMIN_STATUS}.{idx}")
        oper = raw.get(f"{IF_OPER_STATUS}.{idx}")
        interfaces[str(idx)] = {
            "descr": raw.get(f"{IF_DESCR}.{idx}"),
            "admin_status": IF_STATUS_NAMES.get(admin, "unknown") if admin is not None else None,
            "oper_status": IF_STATUS_NAMES.get(oper, "unknown") if oper is not None else None,
            "in_errors": raw.get(f"{IF_IN_ERRORS}.{idx}"),
            "out_errors": raw.get(f"{IF_OUT_ERRORS}.{idx}"),
        }
    return interfaces


def average_cpu(loads: dict[str, Any]) -> float | None:
    values = [v for v in loads.values() if isinstance(v, int)]
    if not values:
        return None
    return round(sum(values) / len(values), 1)


class SnmpProbe(Probe):
    name = "snmp"
    client_factory = SnmpClient

    async def collect(self, host: Host) -> tuple[ProbeStatus, dict[str, Any]]:
        check = host.checks.snmp
        assert check is not None
        creds = self.config.snmp_credentials_for(host)
        if creds is None:
            return ProbeStatus.SKIPPED, {}
        client = self.client_factory(host.address, creds)
        try:
            system = await client.get(SYS_NAME, SYS_DESCR, SYS_UPTIME)
            uptime_ticks = system.get(SYS_UPTIME)
            metrics: dict[str, Any] = {
                "sys_name": system.get(SYS_NAME),
                "sys_descr": system.get(SYS_DESCR),
                "uptime_seconds": uptime_ticks // 100 if isinstance(uptime_ticks, int) else None,
            }
            if check.interfaces:
                oids = [
                    f"{base}.{idx}"
                    for idx in check.interfaces
                    for base in (
                        IF_DESCR,
                        IF_ADMIN_STATUS,
                        IF_OPER_STATUS,
                        IF_IN_ERRORS,
                        IF_OUT_ERRORS,
                    )
                ]
                raw = await client.get(*oids)
                metrics["interfaces"] = parse_interfaces(raw, check.interfaces)
            if check.collect_cpu:
                try:
                    metrics["cpu_pct"] = average_cpu(await client.walk(HR_PROCESSOR_LOAD))
                except SnmpError:
                    metrics["cpu_pct"] = None  # agent doesn't implement HOST-RESOURCES-MIB
        finally:
            client.close()
        return ProbeStatus.OK, metrics
