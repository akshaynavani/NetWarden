# NetWarden — Implementation Plan

NetWarden is a Python network health monitor. It polls an operator-defined list of hosts over
SNMP, checks DNS resolution and DHCP server/pool health, measures NTP clock drift, and probes TCP
service ports. Results are evaluated against thresholds, turned into de-duplicated alerts and
structured reports (JSON / Markdown / console), and optionally mapped to remediation scripts.

## Guiding decisions

- **Explicit inventory only.** NetWarden never scans or discovers. Every probe target must be a
  host declared in `config.yaml`; the probe layer refuses any target not in the inventory.
- **Remediation is opt-in and dry-run by default.** Remediation must be enabled globally in
  config, allowed per host per action, *and* invoked with `--apply`. Otherwise NetWarden only
  writes the generated scripts to disk and records a dry-run entry in the audit log.
- **Async polling.** `asyncio` lets one process poll many hosts concurrently with bounded
  concurrency; blocking libraries (ntplib, raw sockets) run in worker threads.
- **Secrets via environment.** SNMP communities / v3 keys, webhook URLs and SMTP passwords are
  referenced in config as `${ENV_VAR}` and expanded at load time.
- **Linux-first.** Remediation scripts target systemd/chrony hosts reached over SSH.

Stack: Python 3.11+, pysnmp 7 (asyncio hlapi), dnspython, ntplib, PyYAML, pydantic v2, Typer,
SQLite (stdlib) for history, httpx for webhooks, pytest.

## Phase 1 — Project skeleton, configuration and inventory

Deliverables
- Packaging (`pyproject.toml`), `src/` layout, console entry point `netwarden`.
- Pydantic config models: hosts (address, tags, checks, SNMP credentials, allowed remediation
  actions), thresholds, alerting, remediation and storage settings; `${ENV}` expansion.
- `Inventory` that resolves hosts by name and enforces the allowlist.
- Example config and `.env.example`.
- CLI skeleton: `netwarden validate-config`, `netwarden hosts`.

Files: `pyproject.toml`, `config.example.yaml`, `.env.example`, `src/netwarden/__init__.py`,
`config.py`, `inventory.py`, `models.py`, `cli.py`.

## Phase 2 — Probes (SNMP, DNS, DHCP, NTP, TCP)

Deliverables
- Probe base class + `ProbeResult` model with status, metrics and error text.
- SNMP probe: sysUpTime, sysDescr, interface oper status / error counters, CPU (HOST-RESOURCES),
  supports v2c and v3.
- DNS probe: resolve configured records against a specific server, compare against expected
  answers, measure latency.
- DHCP probe: lease-file pool utilisation parser (ISC dhcpd + dnsmasq) and an optional active
  DHCPDISCOVER/OFFER exchange (raw packet builder/parser; needs root).
- NTP probe: offset, delay, stratum via ntplib.
- TCP probe: connect latency for service ports.
- Probe registry + async poller with a concurrency limit and per-probe timeout.

Files: `src/netwarden/probes/{__init__,base,snmp,dns,dhcp,ntp,tcp}.py`, `poller.py`.

## Phase 3 — Evaluation, state and alerting

Deliverables
- Threshold evaluator that turns probe metrics into `Finding`s (ok / warning / critical).
- SQLite state store: poll history and open alerts.
- Alert manager: de-duplication, flap suppression (N consecutive failures), recovery
  notifications.
- Notifiers: console, JSON-lines file, generic webhook (Slack-compatible), SMTP email.

Files: `evaluator.py`, `state.py`, `alerts.py`, `notifiers.py`.

## Phase 4 — Reports and remediation

Deliverables
- Structured reports: JSON, Markdown and Rich console tables.
- Remediation action catalogue (restart service, flush DNS cache, force NTP step, bounce
  interface, restart SNMP agent) with shell templates and finding→action mapping rules.
- Planner that only proposes actions allowed for that host; script generator writing
  reviewable `.sh` files; executor running over SSH only when enabled + `--apply`; audit log.

Files: `reports.py`, `remediation/{__init__,actions,planner,executor}.py`.

## Phase 5 — Runner, CLI commands and tests

Deliverables
- `netwarden check` (one-shot), `netwarden run` (daemon loop with interval),
  `netwarden report`, `netwarden remediate [--apply]`.
- Graceful shutdown on SIGINT/SIGTERM; systemd unit example.
- pytest suite covering config/inventory allowlist, evaluator, DHCP packets and lease parsing,
  alert de-duplication, planner/dry-run behaviour and reports.

Files: `runner.py`, `cli.py`, `deploy/netwarden.service`, `tests/*`.
