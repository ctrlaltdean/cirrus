"""
Collector: Service Principals & Enterprise Applications

Endpoint: GET /servicePrincipals
Requires:  Directory.Read.All

Service principals represent app registrations and enterprise applications
in the tenant. Attackers may:
  - Register a new malicious app with persistent delegated access
  - Add credentials (client secrets / certificates) to existing high-privilege apps
  - Grant themselves application permissions on existing service principals

Key IOCs:
  - Service principals created recently with broad permissions
  - Service principals with many credentials (client secrets/certificates)
  - Service principals not verified / no publisher verification
  - Credentials added to existing high-privilege service principals
"""

from __future__ import annotations

from typing import Any

from cirrus.collectors.base import GRAPH_BASE, GraphCollector
from cirrus.utils.helpers import days_ago_filter


class ServicePrincipalsCollector(GraphCollector):
    name = "service_principals"

    def collect(
        self,
        days: int | None = None,
    ) -> list[dict]:
        """
        Collect service principal records.

        Args:
            days: If set, filter to service principals created in the last N days.

        Returns list of service principal dicts.
        """
        params: dict[str, Any] = {
            "$select": (
                "id,displayName,appId,appDisplayName,appOwnerOrganizationId,"
                "createdDateTime,accountEnabled,servicePrincipalType,"
                "publisherName,verifiedPublisher,oauth2PermissionScopes,"
                "appRoles,keyCredentials,passwordCredentials,"
                "replyUrls,servicePrincipalNames,tags"
            ),
            "$top": 999,
        }

        if days is not None:
            since = days_ago_filter(days)
            params["$filter"] = f"createdDateTime ge {since}"
            params["$count"] = "true"  # createdDateTime requires advanced query support

        records = self._collect_all(f"{GRAPH_BASE}/servicePrincipals", params)

        for sp in records:
            sp["_iocFlags"] = _flag_sp(sp)

        return records


def _flag_sp(sp: dict) -> list[str]:
    flags: list[str] = []

    # No verified publisher
    if not sp.get("verifiedPublisher"):
        flags.append("NO_VERIFIED_PUBLISHER")

    # Multiple credentials (could indicate attacker added a backdoor secret)
    key_creds = sp.get("keyCredentials", [])
    pw_creds = sp.get("passwordCredentials", [])
    total_creds = len(key_creds) + len(pw_creds)
    if total_creds > 2:
        flags.append(f"MANY_CREDENTIALS:{total_creds}")

    # Broad reply URLs (could indicate redirect hijacking)
    reply_urls = sp.get("replyUrls", [])
    for url in reply_urls:
        if "localhost" in url or "127.0.0.1" in url:
            flags.append(f"LOCALHOST_REPLY_URL:{url}")

    # Disabled account still has credentials
    if not sp.get("accountEnabled") and total_creds > 0:
        flags.append("DISABLED_WITH_CREDENTIALS")

    return flags
