"""
Collector: Privileged Identity Management (PIM) Activation History

Endpoint: GET /beta/auditLogs/directoryAudits?$filter=loggedByService eq 'PIM'
Requires:  AuditLog.Read.All  (same as regular audit logs)

PIM activation events are logged under the PIM service and are separate
from the main directory audit stream — they do not appear in standard
`/auditLogs/directoryAudits` queries without the `loggedByService` filter.

This is a critical forensic blind spot: an attacker who gains access to an
account that is eligible for a privileged role can self-activate that role,
perform administrative actions, and deactivate it — all within minutes.
Without this collector, none of that appears in the standard audit log.

Key IOCs surfaced:
  - PIM_ACTIVATION:RoleName — any role activation (always tagged for pivot)
  - HIGH_PRIV_PIM_ACTIVATION:RoleName — activation of a sensitive role
    (Global Admin, Exchange Admin, Privileged Role Admin, etc.)
  - APPROVAL_BYPASSED — role activated without going through the approval workflow
    (may indicate PIM policy was misconfigured or bypassed by a Global Admin)
  - JUSTIFICATION_MISSING — activation submitted with no business justification
    (often required by policy — absence may indicate abuse)
  - ACTIVATION_OUTSIDE_HOURS — activation at unusual time (weekends / overnight)
    relative to the tenant's expected working hours (UTC)
  - SELF_ACTIVATION — user activated their own role (vs. admin-activated for them)
  - PIM_POLICY_CHANGE — PIM role settings were changed (escalation of privileges
    over the PIM system itself)

Why this matters (ATT&CK T1548 — Abuse Elevation Control Mechanism):
  Attackers with any eligible role assignment can activate → act → deactivate
  in a small window. Without PIM audit data, the investigation sees only the
  directory changes the attacker made, not the role activation that enabled them.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from cirrus.collectors.base import GRAPH_BETA, GraphCollector

# ── High-privilege roles — activation always raised as HIGH_PRIV ──────────────
_HIGH_PRIV_ROLES: frozenset[str] = frozenset({
    "global administrator",
    "privileged role administrator",
    "privileged authentication administrator",
    "security administrator",
    "exchange administrator",
    "sharepoint administrator",
    "teams administrator",
    "user administrator",
    "authentication administrator",
    "application administrator",
    "cloud application administrator",
    "conditional access administrator",
    "hybrid identity administrator",
    "directory writers",
})

# Treat activations between these UTC hours as unusual (outside business hours)
# 22:00–06:00 UTC covers overnight; adjust per engagement if needed.
_UNUSUAL_HOUR_START = 22
_UNUSUAL_HOUR_END   = 6   # exclusive (06:00 is okay)

# PIM operation names that indicate a role activation
_ACTIVATION_OPS: frozenset[str] = frozenset({
    "add eligible member to role in pim completed (timebound)",
    "add member to role in pim completed (timebound)",
    "add member to role in pim requested (timebound)",
    "add eligible member to role in pim completed",
    "add member to role in pim completed",
    "add member to role in pim requested",
    "role activation requested",
    "role activation completed",
})

# PIM operations that indicate a policy/settings change
_POLICY_CHANGE_OPS: frozenset[str] = frozenset({
    "update role setting in pim",
    "update role definition in pim",
    "update role assignment in pim",
})


def _extract_role_name(record: dict) -> str:
    """Extract the role name from a PIM audit record."""
    for detail in record.get("additionalDetails") or []:
        key = (detail.get("key") or "").lower()
        if key in ("rolename", "role.displayname", "roledefinition.displayname"):
            val = detail.get("value") or ""
            if val:
                return val
    for res in record.get("targetResources") or []:
        if (res.get("type") or "").lower() in ("role", "roledefinition"):
            name = res.get("displayName") or ""
            if name:
                return name
    return ""


def _extract_justification(record: dict) -> str:
    """Extract the justification text from a PIM activation record."""
    for detail in record.get("additionalDetails") or []:
        key = (detail.get("key") or "").lower()
        if key in ("justification", "reason"):
            return detail.get("value") or ""
    return ""


def _is_unusual_hour(dt_str: str) -> bool:
    """Return True if the timestamp falls outside typical business hours (UTC)."""
    if not dt_str:
        return False
    try:
        dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        hour = dt.hour
        if _UNUSUAL_HOUR_START <= 23 and _UNUSUAL_HOUR_END <= 6:
            return hour >= _UNUSUAL_HOUR_START or hour < _UNUSUAL_HOUR_END
        return False
    except (ValueError, TypeError):
        return False


def _flag_pim_record(record: dict) -> list[str]:
    """Analyse a single PIM audit record and return IOC flag strings."""
    flags: list[str] = []

    activity = (record.get("activityDisplayName") or "").lower().strip()
    ts = record.get("activityDateTime") or ""

    # ── Policy change ──────────────────────────────────────────────────────────
    if any(op in activity for op in _POLICY_CHANGE_OPS):
        flags.append("PIM_POLICY_CHANGE")
        return flags  # no further role-activation checks needed

    # ── Activation events ──────────────────────────────────────────────────────
    is_activation = any(op in activity for op in _ACTIVATION_OPS)
    if not is_activation:
        # Still tag the record so it appears in the collector tab
        flags.append("PIM_EVENT")
        return flags

    role_name = _extract_role_name(record)
    role_lower = role_name.lower()

    # Base activation tag (always present for activations)
    if role_name:
        flags.append(f"PIM_ACTIVATION:{role_name}")
        if role_lower in _HIGH_PRIV_ROLES:
            flags.append(f"HIGH_PRIV_PIM_ACTIVATION:{role_name}")
    else:
        flags.append("PIM_ACTIVATION:unknown_role")

    # ── Justification ──────────────────────────────────────────────────────────
    justification = _extract_justification(record)
    if not justification:
        flags.append("JUSTIFICATION_MISSING")

    # ── Unusual hours ──────────────────────────────────────────────────────────
    if _is_unusual_hour(ts):
        flags.append("ACTIVATION_OUTSIDE_HOURS")

    # ── Self-activation vs admin-activated ────────────────────────────────────
    initiated_by = record.get("initiatedBy") or {}
    initiator_upn = (((initiated_by.get("user") or {}).get("userPrincipalName") or "")).lower()
    target_upns = [
        (res.get("userPrincipalName") or "").lower()
        for res in (record.get("targetResources") or [])
        if (res.get("type") or "").lower() == "user"
    ]
    if initiator_upn and target_upns and initiator_upn in target_upns:
        flags.append("SELF_ACTIVATION")

    # ── Approval status ────────────────────────────────────────────────────────
    result_reason = (record.get("resultReason") or "").lower()
    if "approval" in result_reason and "bypass" in result_reason:
        flags.append("APPROVAL_BYPASSED")

    return flags


class PIMActivationsCollector(GraphCollector):
    """
    Collect Privileged Identity Management activation events from the
    Entra ID audit log stream (beta endpoint, PIM service filter).

    Returns the same record structure as regular audit logs with an added
    _iocFlags list, so the records display correctly in the existing
    audit-log HTML tab and correlation engine.
    """

    name = "pim_activations"

    def collect(
        self,
        days: int = 30,
        users: list[str] | None = None,
        start_dt: datetime | None = None,
        end_dt: datetime | None = None,
    ) -> list[dict]:
        """
        Collect PIM audit events, annotating each record with IOC flags.

        Args:
            days:     How many days back to collect (default 30).
            users:    UPNs to filter on (checks initiator and target).
                      None = all users.
            start_dt: Explicit start (UTC). Overrides days.
            end_dt:   Explicit end (UTC).

        Returns list of PIM audit event dicts, each with _iocFlags.
        """
        self._require_license(
            "p2",
            "PIM activation logs require Entra ID P2 (Privileged Identity Management is a P2 feature).",
        )

        filters = self._build_date_filter(start_dt, end_dt, days, field="activityDateTime")
        filters.append("loggedByService eq 'PIM'")

        params: dict[str, Any] = {
            "$filter": " and ".join(filters),
            "$top": 999,
        }

        records = self._collect_all(f"{GRAPH_BETA}/auditLogs/directoryAudits", params)

        # Per-record flagging
        for record in records:
            record["_iocFlags"] = _flag_pim_record(record)

        # If user filter requested, post-filter (Graph doesn't support user filter
        # on PIM audit logs with loggedByService together in all tenants)
        if users:
            users_lower = {u.lower() for u in users}
            filtered: list[dict] = []
            for record in records:
                initiated_by = record.get("initiatedBy") or {}
                initiator = (((initiated_by.get("user") or {}).get("userPrincipalName") or "")).lower()
                targets = [
                    (res.get("userPrincipalName") or "").lower()
                    for res in (record.get("targetResources") or [])
                    if (res.get("type") or "").lower() == "user"
                ]
                if initiator in users_lower or any(t in users_lower for t in targets):
                    filtered.append(record)
            return filtered

        return records
