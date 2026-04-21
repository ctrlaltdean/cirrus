"""
Collector: Entra ID Directory Audit Logs

Endpoint: GET /auditLogs/directoryAudits
Requires:  AuditLog.Read.All

Captures admin and user-driven changes to the directory:
  - Password resets / changes
  - MFA method additions / removals
  - Role assignments
  - User creation / deletion
  - Application consent grants
  - Conditional Access policy changes

Key IOCs surfaced:
  - MFA method added or removed (persistence / covering tracks)
  - MFA settings changed via Update user (StrongAuthentication property)
  - Admin password reset on a target account (attacker OR incident response)
  - Privileged role assigned — Global Admin, Exchange Admin, etc.
  - App consent granted / delegated permission added (OAuth phishing)
  - Conditional Access policy added, updated, or deleted
  - New app registration or service principal created
  - User created or disabled outside normal provisioning windows
  - Public IP extracted from additionalDetails where present
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from cirrus.collectors.base import GRAPH_BASE, GraphCollector
from cirrus.utils.helpers import is_private_ip

# ── High-privilege roles — assignment always flagged separately ───────────────
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
    "conditional access administrator",
    "application administrator",
    "cloud application administrator",
    "helpdesk administrator",
    "hybrid identity administrator",
    "global reader",              # broad read access — watch for unexpected grants
    "directory writers",
})


def _extract_role_name(record: dict) -> str | None:
    """
    Extract the role display name from an audit record.

    Checks additionalDetails first (most reliable), then falls back to
    scanning targetResources for an object of type Role.
    """
    for detail in record.get("additionalDetails") or []:
        key = detail.get("key") or ""
        if key.lower() in ("role.displayname", "roledefinition.displayname", "targetupdatedproperties"):
            val = detail.get("value") or ""
            if val:
                return val

    for resource in record.get("targetResources") or []:
        if (resource.get("type") or "").lower() == "role":
            return resource.get("displayName")

    return None


def _extract_ip(record: dict) -> str | None:
    """
    Extract a public IP from a record's additionalDetails, if present.

    Some audit events (e.g. SSPR, consent) include the initiating IP.
    Returns None if the IP is private/loopback or not found.
    """
    for detail in record.get("additionalDetails") or []:
        key = (detail.get("key") or "").lower()
        if key in ("ipaddr", "ipaddress", "ip"):
            ip = detail.get("value") or ""
            if ip and not is_private_ip(ip):
                return ip
    return None


def _flag_audit_event(record: dict) -> list[str]:
    """
    Analyse a single directory audit record and return IOC flag strings.

    Flags cover:
      - User lifecycle events (create, delete, disable)
      - Credential operations (password reset/change)
      - MFA / strong authentication changes
      - Role assignments (including high-privilege role callout)
      - OAuth / app consent and permission grants
      - Conditional Access policy changes
      - App registration and service principal creation
      - Operation failures
      - Public IP present in the audit record
    """
    flags: list[str] = []

    activity = (record.get("activityDisplayName") or "").strip()
    activity_lc = activity.lower()
    result = (record.get("result") or "").lower()

    # ── Failed operations ─────────────────────────────────────────────────────
    if result in ("failure", "timeout"):
        flags.append(f"OPERATION_FAILED:{activity}")

    # ── User lifecycle ────────────────────────────────────────────────────────
    if activity_lc == "add user":
        flags.append("USER_CREATED")

    elif activity_lc == "delete user":
        flags.append("USER_DELETED")

    elif activity_lc in ("block sign in", "block sign-in"):
        flags.append("USER_DISABLED")

    elif activity_lc in ("unblock sign in", "unblock sign-in"):
        flags.append("USER_ENABLED")

    # ── Credential operations ─────────────────────────────────────────────────
    elif activity_lc == "reset user password":
        # Could be attacker clearing the victim's ability to recover, or
        # legitimate incident response — always flag for manual review.
        flags.append("ADMIN_PASSWORD_RESET")

    elif activity_lc in ("change user password", "user changed password"):
        flags.append("USER_PASSWORD_CHANGE")

    # ── MFA / authentication method changes ───────────────────────────────────
    elif "registered security info" in activity_lc:
        # "User registered security info" — new MFA method added by the user
        flags.append("MFA_METHOD_ADDED")

    elif "deleted security info" in activity_lc:
        # "User deleted security info" — MFA method removed
        flags.append("MFA_METHOD_REMOVED")

    elif "registered all required security info" in activity_lc:
        flags.append("MFA_REGISTRATION_COMPLETE")

    elif activity_lc == "update user":
        # StrongAuthentication property changes are surfaced as Update user
        # events with modifiedProperties entries whose displayName contains
        # "StrongAuthentication" or "AuthenticationMethod".
        for resource in record.get("targetResources") or []:
            for prop in resource.get("modifiedProperties") or []:
                prop_name = (prop.get("displayName") or "").lower()
                if "strongauth" in prop_name or "authenticationmethod" in prop_name:
                    flags.append("MFA_SETTINGS_CHANGED")
                    break

    # ── Role assignment / removal ─────────────────────────────────────────────
    elif "add member to role" in activity_lc or "add eligible member to role" in activity_lc:
        role_name = _extract_role_name(record)
        flags.append(f"ROLE_ASSIGNMENT:{role_name}" if role_name else "ROLE_ASSIGNMENT")
        if role_name and role_name.lower() in _HIGH_PRIV_ROLES:
            flags.append(f"HIGH_PRIV_ROLE_ASSIGNED:{role_name}")

    elif "remove member from role" in activity_lc:
        role_name = _extract_role_name(record)
        flags.append(f"ROLE_REMOVAL:{role_name}" if role_name else "ROLE_REMOVAL")

    # ── OAuth / application consent ───────────────────────────────────────────
    elif activity_lc in ("consent to application", "add oauth2permissiongrant"):
        flags.append("APP_CONSENT_GRANTED")

    elif "oauth2permissiongrant" in activity_lc:
        flags.append("OAUTH_PERMISSION_CHANGED")

    # ── Conditional Access policy changes ─────────────────────────────────────
    elif "conditional access policy" in activity_lc:
        if "add" in activity_lc:
            flags.append("CA_POLICY_ADDED")
        elif "update" in activity_lc:
            flags.append("CA_POLICY_UPDATED")
        elif "delete" in activity_lc:
            flags.append("CA_POLICY_DELETED")
        else:
            flags.append("CA_POLICY_CHANGED")

    # ── App registration / service principal ──────────────────────────────────
    elif activity_lc == "add application":
        flags.append("APP_REGISTRATION_CREATED")

    elif activity_lc in ("update application", "update application – certificates and secrets management"):
        flags.append("APP_REGISTRATION_UPDATED")

    elif activity_lc in ("add service principal", "add service principal credentials"):
        flags.append("SERVICE_PRINCIPAL_ADDED")

    elif activity_lc == "add owner to application":
        flags.append("APP_OWNER_ADDED")

    # ── IP address (when available in additionalDetails) ──────────────────────
    ip = _extract_ip(record)
    if ip:
        flags.append(f"PUBLIC_IP:{ip}")

    return flags


class AuditLogsCollector(GraphCollector):
    name = "entra_audit_logs"

    def collect(
        self,
        days: int = 30,
        users: list[str] | None = None,
        start_dt: datetime | None = None,
        end_dt: datetime | None = None,
    ) -> list[dict]:
        """
        Collect Entra directory audit logs, annotating each record with IOC flags.

        Args:
            days:     How many days back to collect (default 30).
                      Ignored when start_dt is provided.
            users:    Filter by initiatedBy UPN. None = all.
            start_dt: Explicit collection start (UTC). Overrides days.
            end_dt:   Explicit collection end (UTC). Adds an upper bound filter.

        Returns list of audit event dicts, each with an _iocFlags list.
        """
        filters = self._build_date_filter(start_dt, end_dt, days, field="activityDateTime")

        if users:
            user_filters = " or ".join(
                f"initiatedBy/user/userPrincipalName eq '{u}'" for u in users
            )
            filters.append(f"({user_filters})")

        params: dict[str, Any] = {
            "$filter": " and ".join(filters),
            "$top": 999,
            "$orderby": "activityDateTime desc",
            "$select": (
                "id,activityDateTime,activityDisplayName,category,correlationId,"
                "initiatedBy,loggedByService,operationType,result,resultReason,"
                "targetResources,additionalDetails"
            ),
        }

        # Nested property filters (initiatedBy/user/userPrincipalName) require
        # advanced query support. The ConsistencyLevel: eventual header is set
        # globally on the session and is sufficient — $count=true is NOT added
        # here because /auditLogs/directoryAudits returns 400 "query option
        # Count is not allowed" when $count is included.

        records = self._collect_all(f"{GRAPH_BASE}/auditLogs/directoryAudits", params)

        for record in records:
            record["_iocFlags"] = _flag_audit_event(record)

        return records
