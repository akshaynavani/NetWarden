from __future__ import annotations

from typing import Any

import pytest

from netwarden.config import NetWardenConfig, parse_config
from netwarden.inventory import Inventory


def base_raw(tmp_path) -> dict[str, Any]:
    return {
        "defaults": {"snmp": {"version": "2c", "community": "public-test"}},
        "alerting": {"consecutive_failures": 2, "notifiers": [{"type": "console"}]},
        "remediation": {
            "enabled": False,
            "script_dir": str(tmp_path / "scripts"),
            "audit_log": str(tmp_path / "audit.jsonl"),
        },
        "storage": {
            "sqlite_path": str(tmp_path / "nw.db"),
            "report_dir": str(tmp_path / "reports"),
        },
        "hosts": [
            {
                "name": "dns-01",
                "address": "192.0.2.10",
                "tags": ["dns", "linux"],
                "checks": {
                    "dns": {"records": [{"name": "a.example", "type": "A", "expect": ["10.0.0.1"]}]},
                    "ntp": {},
                    "tcp": {"ports": [22, 53]},
                },
                "remediation": {
                    "ssh_user": "netops",
                    "allowed_actions": ["restart_service", "flush_dns_cache", "ntp_step"],
                    "services": ["named", "chrony"],
                },
            },
            {
                "name": "sw-01",
                "address": "192.0.2.2",
                "tags": ["switch"],
                "checks": {"snmp": {"interfaces": [1, 2]}},
            },
        ],
    }


@pytest.fixture
def raw_config(tmp_path) -> dict[str, Any]:
    return base_raw(tmp_path)


@pytest.fixture
def config(raw_config) -> NetWardenConfig:
    return parse_config(raw_config)


@pytest.fixture
def inventory(config) -> Inventory:
    return Inventory(config)
