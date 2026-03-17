"""
Collector: Entra ID Sign-In Logs

Endpoint: GET /auditLogs/signIns
Requires:  AuditLog.Read.All

Collects interactive and non-interactive sign-in events.
Supports filtering by user(s) and date range.

Key IOCs surfaced:
  - Sign-ins from new/unusual countries or IPs
  - Sign-ins with legacy auth protocols (BasicAuth, IMAP, SMTP, etc.)
  - Failed sign-ins followed by successful sign-in (brute force)
  - MFA not satisfied / MFA bypassed
  - Conditional Access policy failures
  - Token-only sign-ins (no MFA, device compliance not checked)
"""

from __future__ import annotations

from typing import Any

from cirrus.collectors.base import GRAPH_BASE, GraphCollector
from cirrus.utils.helpers import days_ago_filter


class SignInLogsCollector(GraphCollector):
    name = "signin_logs"

    def collect(
        self,
        days: int = 30,
        users: list[str] | None = None,
    ) -> list[dict]:
        """
        Collect sign-in logs.

        Args:
            days:  How many days back to collect (default 30).
            users: List of UPNs to filter on.
                   None = collect all users.

        Returns list of sign-in event dicts.
        """
        since = days_ago_filter(days)
        filters = [f"createdDateTime ge {since}"]

        if users:
            user_filters = " or ".join(
                f"userPrincipalName eq '{u}'" for u in users
            )
            filters.append(f"({user_filters})")

        params: dict[str, Any] = {
            "$filter": " and ".join(filters),
            "$top": 999,
            "$orderby": "createdDateTime desc",
            "$select": (
                "id,createdDateTime,userDisplayName,userPrincipalName,userId,"
                "appDisplayName,appId,ipAddress,location,clientAppUsed,"
                "conditionalAccessStatus,isInteractive,mfaDetail,"
                "riskDetail,riskEventTypes,riskLevelAggregated,riskLevelDuringSignIn,"
                "riskState,status,deviceDetail,authenticationDetails,"
                "authenticationRequirement,homeTenantId,resourceDisplayName,resourceId,"
                "flaggedForReview,tokenIssuerType,networkLocationDetails"
            ),
        }

        records = self._collect_all(f"{GRAPH_BASE}/auditLogs/signIns", params)
        return records
