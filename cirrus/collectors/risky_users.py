"""
Collector: Risky Users & Risky Sign-Ins (Identity Protection)

Endpoints:
  GET /identityProtection/riskyUsers
  GET /identityProtection/riskySignIns

Requires:
  IdentityRiskyUser.Read.All
  IdentityRiskEvent.Read.All

Microsoft Entra ID Protection scores users and sign-ins for risk.
This data surfaces:
  - Accounts Microsoft has already flagged as compromised
  - Leaked credentials detected by Microsoft threat intelligence
  - Impossible travel sign-ins
  - Anonymous IP usage
  - Malware-linked IP addresses
  - Password spray / brute force patterns

Key IOCs:
  - riskLevel = high / medium for target users
  - riskState = atRisk or confirmedCompromised
  - Sign-in risk detail: leakedCredentials, anonymizedIPAddress, etc.
"""

from __future__ import annotations

from typing import Any

from cirrus.collectors.base import GRAPH_BASE, GraphCollector
from cirrus.utils.helpers import days_ago_filter


class RiskyUsersCollector(GraphCollector):
    name = "risky_users"

    def collect(
        self,
        users: list[str] | None = None,
        risk_levels: list[str] | None = None,
    ) -> list[dict]:
        """
        Collect risky user records.

        Args:
            users:       Filter to specific UPNs.
            risk_levels: Filter to specific risk levels
                         (e.g., ["high", "medium"]).

        Returns list of risky user dicts.
        """
        filters: list[str] = []

        if risk_levels:
            level_filter = " or ".join(f"riskLevel eq '{lvl}'" for lvl in risk_levels)
            filters.append(f"({level_filter})")

        params: dict[str, Any] = {
            "$select": (
                "id,userDisplayName,userPrincipalName,riskDetail,"
                "riskLastUpdatedDateTime,riskLevel,riskState,isDeleted,isProcessing"
            ),
            "$top": 999,
        }
        if filters:
            params["$filter"] = " and ".join(filters)

        records = self._collect_all(f"{GRAPH_BASE}/identityProtection/riskyUsers", params)

        # If user filter was provided, filter client-side (UPN filter not supported server-side)
        if users:
            upn_set = {u.lower() for u in users}
            records = [
                r for r in records
                if r.get("userPrincipalName", "").lower() in upn_set
            ]

        return records


class RiskySignInsCollector(GraphCollector):
    name = "risky_signins"

    def collect(
        self,
        days: int = 30,
        users: list[str] | None = None,
    ) -> list[dict]:
        """
        Collect risky sign-in events.

        Args:
            days:  How many days back to collect.
            users: Filter to specific UPNs.

        Returns list of risky sign-in dicts.
        """
        since = days_ago_filter(days)
        filters = [f"createdDateTime ge {since}"]

        if users:
            user_filter = " or ".join(
                f"userPrincipalName eq '{u}'" for u in users
            )
            filters.append(f"({user_filter})")

        params: dict[str, Any] = {
            "$filter": " and ".join(filters),
            "$select": (
                "id,createdDateTime,userDisplayName,userPrincipalName,userId,"
                "ipAddress,location,riskDetail,riskEventTypes,riskEventTypes_v2,"
                "riskLevelAggregated,riskLevelDuringSignIn,riskState,status,"
                "deviceDetail,clientAppUsed,appDisplayName"
            ),
            "$top": 999,
            "$orderby": "createdDateTime desc",
        }

        return self._collect_all(
            f"{GRAPH_BASE}/identityProtection/riskySignIns", params
        )
