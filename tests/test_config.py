import pytest

from netwarden.config import ConfigError, expand_env, parse_config
from netwarden.inventory import Inventory, TargetNotAllowed


def test_valid_config_parses(config):
    assert [h.name for h in config.hosts] == ["dns-01", "sw-01"]
    assert config.remediation.enabled is False


def test_remediation_disabled_by_default(raw_config):
    raw_config.pop("remediation")
    cfg = parse_config(raw_config)
    assert cfg.remediation.enabled is False


def test_env_expansion(monkeypatch):
    monkeypatch.setenv("NW_TEST_SECRET", "s3cret")
    assert expand_env({"a": ["${NW_TEST_SECRET}"]}) == {"a": ["s3cret"]}
    assert expand_env("${NW_MISSING_VAR:-fallback}") == "fallback"


def test_missing_env_var_is_an_error():
    with pytest.raises(ConfigError):
        expand_env("${NW_DEFINITELY_NOT_SET_12345}")


def test_cidr_addresses_are_rejected(raw_config):
    raw_config["hosts"][0]["address"] = "10.0.0.0/24"
    with pytest.raises(ConfigError, match="single host"):
        parse_config(raw_config)


def test_duplicate_hosts_rejected(raw_config):
    raw_config["hosts"][1]["name"] = "dns-01"
    with pytest.raises(ConfigError, match="duplicate"):
        parse_config(raw_config)


def test_unknown_remediation_action_rejected(raw_config):
    raw_config["hosts"][0]["remediation"]["allowed_actions"] = ["rm_rf"]
    with pytest.raises(ConfigError, match="unknown remediation"):
        parse_config(raw_config)


def test_snmp_requires_credentials(raw_config):
    raw_config.pop("defaults")
    with pytest.raises(ConfigError, match="no credentials"):
        parse_config(raw_config)


def test_threshold_override(config):
    host = config.hosts[0]
    host.thresholds = {"cpu_warn_pct": 50}
    assert config.thresholds_for(host).cpu_warn_pct == 50
    assert config.thresholds.cpu_warn_pct == 80


def test_inventory_allowlist(inventory):
    assert inventory.get("sw-01").address == "192.0.2.2"
    inventory.require_address("192.0.2.10")
    with pytest.raises(TargetNotAllowed):
        inventory.get("intruder")
    with pytest.raises(TargetNotAllowed):
        inventory.require_address("8.8.8.8")


def test_inventory_select_by_tag(inventory):
    assert [h.name for h in inventory.select(tags=["switch"])] == ["sw-01"]
    assert len(inventory.select()) == 2


def test_example_config_is_valid(monkeypatch):
    from pathlib import Path

    from netwarden.config import load_config

    for var in ("NETWARDEN_SNMP_COMMUNITY", "NETWARDEN_SNMPV3_AUTH_KEY", "NETWARDEN_SNMPV3_PRIV_KEY"):
        monkeypatch.setenv(var, "x" * 12)
    cfg = load_config(Path(__file__).parent.parent / "config.example.yaml")
    assert len(Inventory(cfg)) == 3
