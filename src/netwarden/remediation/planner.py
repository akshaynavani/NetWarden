"""Build a remediation plan from findings, honouring each host's allowed actions."""

from __future__ import annotations

from netwarden.inventory import Inventory, TargetNotAllowed
from netwarden.models import Finding, Severity
from netwarden.remediation.actions import ACTION_PLANNERS, PlannedAction, UnsafeParameter


def plan_remediation(inventory: Inventory, findings: list[Finding]) -> list[PlannedAction]:
    """Return de-duplicated actions for non-OK findings on hosts that allow them.

    A host with no ``allowed_actions`` never gets a plan entry -- remediation is opt-in per
    host as well as globally.
    """
    planned: dict[tuple, PlannedAction] = {}
    for f in findings:
        if f.severity == Severity.OK:
            continue
        try:
            host = inventory.get(f.host)
        except TargetNotAllowed:
            continue
        for action_name in host.remediation.allowed_actions:
            planner = ACTION_PLANNERS.get(action_name)
            if planner is None:
                continue
            try:
                action = planner(host, f)
            except UnsafeParameter:
                continue
            if action is not None and action.dedupe_key not in planned:
                planned[action.dedupe_key] = action
    return list(planned.values())
