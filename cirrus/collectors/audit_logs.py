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
  - MFA method added shortly after a successful sign-in (persistence)
  - Password reset by admin (account takeover response OR attacker covering tracks)
  - New app consent granted (OAuth phishing)
  - Privileged role assignment to unexpected user
"""

from __future__ import annotations

from typing import Any

from cirrus.collectors.base import GRAPH_BASE, GraphCollector
from cirrus.utils.helpers import days_ago_filter


class AuditLogsCollector(GraphCollector):
    name = "entra_audit_logs"

    def collect(
        self,
        days: int = 30,
        users: list[str] | None = None,
    ) -> list[dict]:
        """
        Collect Entra directory audit logs.

        Args:
            days:  How many days back to collect (default 30).
            users: Filter by initiatedBy UPN. None = all.

        Returns list of audit event dicts.
        """
        since = days_ago_filter(days)
        filters = [f"activityDateTime ge {since}"]

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
        # advanced query support: ConsistencyLevel header (set globally) + $count=true.
        # Without $count, combining a nested filter with $orderby can return 400.
        if users:
            params["$count"] = "true"

        records = self._collect_all(f"{GRAPH_BASE}/auditLogs/directoryAudits", params)
        return records
