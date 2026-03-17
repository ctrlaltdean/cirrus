"""
Collector: Entra ID Users Directory

Endpoint: GET /users
Requires:  User.Read.All

Collects the full user directory. Useful for:
  - Building a complete user list for targeted collection
  - Identifying recently created accounts (attacker persistence)
  - Identifying accounts without MFA registration
  - Identifying external / guest accounts with unusual permissions
  - Identifying admin accounts

Key IOCs:
  - Accounts created during the incident window
  - Accounts with no MFA registered (onPremisesImmutableId is null = cloud-only)
  - Guest accounts with elevated permissions
  - Accounts with suspicious UPN patterns
"""

from __future__ import annotations

from typing import Any

from cirrus.collectors.base import GRAPH_BASE, GraphCollector
from cirrus.utils.helpers import days_ago_filter


class UsersCollector(GraphCollector):
    name = "users"

    def collect(
        self,
        days: int | None = None,
        users: list[str] | None = None,
    ) -> list[dict]:
        """
        Collect user directory records.

        Args:
            days:  If set, filter to users created in the last N days.
            users: If set, collect only these specific UPNs.

        Returns list of user dicts.
        """
        if users:
            records: list[dict] = []
            for upn in users:
                try:
                    user = self._get(
                        f"{GRAPH_BASE}/users/{upn}",
                        params={"$select": _USER_SELECT},
                    )
                    records.append(user)
                except Exception as e:
                    records.append({"_requestedUser": upn, "_error": str(e)})
            return records

        params: dict[str, Any] = {
            "$select": _USER_SELECT,
            "$top": 999,
        }

        if days is not None:
            since = days_ago_filter(days)
            params["$filter"] = f"createdDateTime ge {since}"
            params["$count"] = "true"  # createdDateTime requires advanced query support

        return self._collect_all(f"{GRAPH_BASE}/users", params)


_USER_SELECT = (
    "id,displayName,userPrincipalName,mail,userType,accountEnabled,"
    "createdDateTime,lastPasswordChangeDateTime,onPremisesLastSyncDateTime,"
    "onPremisesImmutableId,onPremisesSyncEnabled,assignedLicenses,"
    "jobTitle,department,officeLocation,city,country,usageLocation,"
    "proxyAddresses,otherMails,identities"
)
