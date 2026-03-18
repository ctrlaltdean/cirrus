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

from datetime import datetime
from typing import Any

from cirrus.collectors.base import GRAPH_BASE, GraphCollector
from cirrus.utils.helpers import days_ago_filter, dt_to_odata


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
        self._require_license(
            "p2",
            "Identity Protection (riskyUsers) requires Entra ID P2 or Microsoft 365 E5. "
            "This tenant appears to be licensed at P1 only.",
        )

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

        # Server-side UPN filter requires advanced queries (ConsistencyLevel header
        # already set globally). Apply it here to avoid fetching all risky users
        # when we only need a subset.
        if users:
            upn_filter = " or ".join(f"userPrincipalName eq '{u}'" for u in users)
            existing = params.get("$filter", "")
            params["$filter"] = f"({existing}) and ({upn_filter})" if existing else f"({upn_filter})"
            params["$count"] = "true"

        return self._collect_all(f"{GRAPH_BASE}/identityProtection/riskyUsers", params)


class RiskySignInsCollector(GraphCollector):
    name = "risky_signins"

    def collect(
        self,
        days: int = 30,
        users: list[str] | None = None,
        start_dt: datetime | None = None,
        end_dt: datetime | None = None,
    ) -> list[dict]:
        """
        Collect risky sign-in events.

        Args:
            days:     How many days back to collect.
                      Ignored when start_dt is provided.
            users:    Filter to specific UPNs.
            start_dt: Explicit collection start (UTC). Overrides days.
            end_dt:   Explicit collection end (UTC). Adds an upper bound filter.

        Returns list of risky sign-in dicts.
        """
        self._require_license(
            "p2",
            "Identity Protection (riskySignIns) requires Entra ID P2 or Microsoft 365 E5. "
            "This tenant appears to be licensed at P1 only.",
        )

        since = dt_to_odata(start_dt) if start_dt else days_ago_filter(days)
        filters = [f"createdDateTime ge {since}"]

        if end_dt is not None:
            filters.append(f"createdDateTime le {dt_to_odata(end_dt)}")

        if users:
            user_filter = " or ".join(
                f"userPrincipalName eq '{u}'" for u in users
            )
            filters.append(f"({user_filter})")

        params: dict[str, Any] = {
            "$filter": " and ".join(filters),
            "$select": (
                "id,createdDateTime,userDisplayName,userPrincipalName,userId,"
                "ipAddress,location,riskDetail,riskEventTypes_v2,"
                "riskLevelAggregated,riskLevelDuringSignIn,riskState,"
                "deviceDetail,clientAppUsed"
            ),
            "$top": 999,
        }

        return self._collect_all(
            f"{GRAPH_BASE}/identityProtection/riskySignIns", params
        )
