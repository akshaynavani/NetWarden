"""Configuration models and loader.

The config file is the single source of truth for what NetWarden is allowed to touch: only the
hosts listed under ``hosts`` are ever probed, and remediation is disabled unless explicitly
switched on.
"""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")

KNOWN_ACTIONS = {
    "restart_service",
    "flush_dns_cache",
    "ntp_step",
    "bounce_interface",
    "renew_dhcp_lease",
}


class ConfigError(Exception):
    """Raised when the configuration file is missing or invalid."""


# --------------------------------------------------------------------------- SNMP


class SnmpCredentials(BaseModel):
    version: Literal["2c", "3"] = "2c"
    community: str | None = None
    port: int = 161
    timeout: float = 2.0
    retries: int = 1
    # SNMPv3 (USM)
    username: str | None = None
    auth_protocol: Literal["SHA", "SHA256", "MD5"] | None = None
    auth_key: str | None = None
    priv_protocol: Literal["AES", "AES256", "DES"] | None = None
    priv_key: str | None = None

    @model_validator(mode="after")
    def _check_version_fields(self) -> "SnmpCredentials":
        if self.version == "2c" and not self.community:
            raise ValueError("SNMP v2c requires a community string")
        if self.version == "3" and not self.username:
            raise ValueError("SNMP v3 requires a username")
        if self.priv_key and not self.auth_key:
            raise ValueError("SNMP v3 privacy requires an auth key as well")
        return self


# --------------------------------------------------------------------------- checks


class SnmpCheck(BaseModel):
    enabled: bool = True
    interfaces: list[int] = Field(default_factory=list, description="ifIndex values to watch")
    collect_cpu: bool = True
    credentials: SnmpCredentials | None = None


class DnsRecordCheck(BaseModel):
    name: str
    type: Literal["A", "AAAA", "CNAME", "MX", "TXT", "PTR", "NS", "SRV"] = "A"
    expect: list[str] = Field(default_factory=list)


class DnsCheck(BaseModel):
    """Query this host (acting as a DNS server) for the listed records."""

    port: int = 53
    records: list[DnsRecordCheck] = Field(default_factory=list)


class DhcpCheck(BaseModel):
    lease_file: Path | None = None
    lease_format: Literal["isc", "dnsmasq"] = "isc"
    pool_size: int | None = Field(default=None, ge=1)
    active_probe: bool = False
    interface: str | None = None

    @model_validator(mode="after")
    def _needs_something(self) -> "DhcpCheck":
        if self.lease_file is None and not self.active_probe:
            raise ValueError("dhcp check needs a lease_file and/or active_probe: true")
        if self.lease_file is not None and self.pool_size is None:
            raise ValueError("dhcp lease_file checks need pool_size to compute utilisation")
        return self


class NtpCheck(BaseModel):
    version: int = 3
    port: int = 123


class TcpCheck(BaseModel):
    ports: list[int] = Field(default_factory=list)

    @field_validator("ports")
    @classmethod
    def _valid_ports(cls, v: list[int]) -> list[int]:
        for p in v:
            if not 0 < p < 65536:
                raise ValueError(f"invalid TCP port {p}")
        return v


class HostChecks(BaseModel):
    snmp: SnmpCheck | None = None
    dns: DnsCheck | None = None
    dhcp: DhcpCheck | None = None
    ntp: NtpCheck | None = None
    tcp: TcpCheck | None = None

    def enabled(self) -> list[str]:
        names = []
        for name in ("snmp", "dns", "dhcp", "ntp", "tcp"):
            check = getattr(self, name)
            if check is None:
                continue
            if name == "snmp" and not check.enabled:
                continue
            names.append(name)
        return names


# --------------------------------------------------------------------------- thresholds


class Thresholds(BaseModel):
    ntp_offset_warn_ms: float = 100.0
    ntp_offset_crit_ms: float = 500.0
    ntp_max_stratum: int = 5
    dns_latency_warn_ms: float = 200.0
    dns_latency_crit_ms: float = 1000.0
    tcp_latency_warn_ms: float = 300.0
    tcp_latency_crit_ms: float = 1500.0
    cpu_warn_pct: float = 80.0
    cpu_crit_pct: float = 95.0
    if_errors_warn: int = 100
    if_errors_crit: int = 1000
    dhcp_pool_warn_pct: float = 80.0
    dhcp_pool_crit_pct: float = 95.0
    min_uptime_seconds: int = 600

    @model_validator(mode="after")
    def _ordered(self) -> "Thresholds":
        pairs = [
            ("ntp_offset_warn_ms", "ntp_offset_crit_ms"),
            ("dns_latency_warn_ms", "dns_latency_crit_ms"),
            ("tcp_latency_warn_ms", "tcp_latency_crit_ms"),
            ("cpu_warn_pct", "cpu_crit_pct"),
            ("if_errors_warn", "if_errors_crit"),
            ("dhcp_pool_warn_pct", "dhcp_pool_crit_pct"),
        ]
        for warn, crit in pairs:
            if getattr(self, warn) > getattr(self, crit):
                raise ValueError(f"{warn} must not exceed {crit}")
        return self


# --------------------------------------------------------------------------- hosts


class HostRemediation(BaseModel):
    ssh_user: str | None = None
    ssh_port: int = 22
    allowed_actions: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list, description="services we may restart")
    interfaces: list[str] = Field(default_factory=list, description="interfaces we may bounce")

    @field_validator("allowed_actions")
    @classmethod
    def _known(cls, v: list[str]) -> list[str]:
        unknown = set(v) - KNOWN_ACTIONS
        if unknown:
            raise ValueError(f"unknown remediation actions: {sorted(unknown)}")
        return v


class Host(BaseModel):
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    address: str
    tags: list[str] = Field(default_factory=list)
    checks: HostChecks = Field(default_factory=HostChecks)
    thresholds: dict[str, float] = Field(default_factory=dict)
    remediation: HostRemediation = Field(default_factory=HostRemediation)

    @field_validator("address")
    @classmethod
    def _no_networks(cls, v: str) -> str:
        # Hosts must be single addresses or hostnames -- never CIDR ranges. NetWarden does not
        # sweep networks.
        if "/" in v:
            raise ValueError("address must be a single host, not a network range")
        try:
            ipaddress.ip_address(v)
        except ValueError:
            if not re.fullmatch(r"[A-Za-z0-9.-]+", v):
                raise ValueError(f"invalid host address {v!r}") from None
        return v

    @field_validator("thresholds")
    @classmethod
    def _known_thresholds(cls, v: dict[str, float]) -> dict[str, float]:
        unknown = set(v) - set(Thresholds.model_fields)
        if unknown:
            raise ValueError(f"unknown threshold overrides: {sorted(unknown)}")
        return v


# --------------------------------------------------------------------------- global sections


class PollingConfig(BaseModel):
    interval_seconds: int = Field(default=60, ge=5)
    concurrency: int = Field(default=20, ge=1, le=500)
    probe_timeout_seconds: float = Field(default=10.0, gt=0)


class NotifierConfig(BaseModel):
    type: Literal["console", "jsonl", "webhook", "email"]
    min_severity: Literal["warning", "critical"] = "warning"
    path: Path | None = None
    url: str | None = None
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None
    sender: str | None = None
    recipients: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _required_fields(self) -> "NotifierConfig":
        if self.type == "jsonl" and self.path is None:
            raise ValueError("jsonl notifier needs a path")
        # An empty url (e.g. "${NETWARDEN_WEBHOOK_URL:-}") disables the webhook.
        if self.type == "webhook" and self.url is None:
            raise ValueError("webhook notifier needs a url key (may be empty to disable)")
        if self.type == "email" and not (self.smtp_host and self.sender and self.recipients):
            raise ValueError("email notifier needs smtp_host, sender and recipients")
        return self


class AlertingConfig(BaseModel):
    consecutive_failures: int = Field(default=2, ge=1)
    notify_on_recovery: bool = True
    renotify_minutes: int = Field(default=60, ge=0)
    notifiers: list[NotifierConfig] = Field(
        default_factory=lambda: [NotifierConfig(type="console")]
    )


class RemediationConfig(BaseModel):
    enabled: bool = False
    script_dir: Path = Path("./remediation_scripts")
    audit_log: Path = Path("./data/remediation_audit.jsonl")
    ssh_key_path: str | None = None
    ssh_options: list[str] = Field(
        default_factory=lambda: ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
    )
    command_timeout_seconds: int = 60


class StorageConfig(BaseModel):
    sqlite_path: Path = Path("./data/netwarden.db")
    report_dir: Path = Path("./reports")
    history_days: int = 14


class Defaults(BaseModel):
    snmp: SnmpCredentials | None = None


class NetWardenConfig(BaseModel):
    defaults: Defaults = Field(default_factory=Defaults)
    thresholds: Thresholds = Field(default_factory=Thresholds)
    polling: PollingConfig = Field(default_factory=PollingConfig)
    alerting: AlertingConfig = Field(default_factory=AlertingConfig)
    remediation: RemediationConfig = Field(default_factory=RemediationConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    hosts: list[Host]

    @model_validator(mode="after")
    def _unique_hosts(self) -> "NetWardenConfig":
        if not self.hosts:
            raise ValueError("at least one host must be listed")
        names = [h.name for h in self.hosts]
        dupes = {n for n in names if names.count(n) > 1}
        if dupes:
            raise ValueError(f"duplicate host names: {sorted(dupes)}")
        for host in self.hosts:
            snmp = host.checks.snmp
            if snmp and snmp.enabled and snmp.credentials is None and self.defaults.snmp is None:
                raise ValueError(f"host {host.name}: SNMP enabled but no credentials configured")
        return self

    def snmp_credentials_for(self, host: Host) -> SnmpCredentials | None:
        if host.checks.snmp and host.checks.snmp.credentials:
            return host.checks.snmp.credentials
        return self.defaults.snmp

    def thresholds_for(self, host: Host) -> Thresholds:
        if not host.thresholds:
            return self.thresholds
        return self.thresholds.model_copy(update=host.thresholds)


# --------------------------------------------------------------------------- loading


def expand_env(value: Any) -> Any:
    """Recursively replace ``${VAR}`` / ``${VAR:-default}`` in strings with env values."""
    if isinstance(value, str):

        def repl(match: re.Match[str]) -> str:
            name, default = match.group(1), match.group(2)
            if name in os.environ:
                return os.environ[name]
            if default is not None:
                return default
            raise ConfigError(f"environment variable {name} is referenced but not set")

        return ENV_PATTERN.sub(repl, value)
    if isinstance(value, list):
        return [expand_env(v) for v in value]
    if isinstance(value, dict):
        return {k: expand_env(v) for k, v in value.items()}
    return value


def parse_config(raw: dict[str, Any]) -> NetWardenConfig:
    try:
        return NetWardenConfig.model_validate(expand_env(raw))
    except ValidationError as exc:
        raise ConfigError(str(exc)) from exc


def load_config(path: str | Path) -> NetWardenConfig:
    path = Path(path)
    if not path.is_file():
        raise ConfigError(f"config file not found: {path}")
    with path.open() as fh:
        raw = yaml.safe_load(fh) or {}
    if not isinstance(raw, dict):
        raise ConfigError("config root must be a mapping")
    return parse_config(raw)
