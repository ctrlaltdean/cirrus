"""
Collector: Unified Audit Log (UAL)

Endpoint: POST /beta/security/auditLog/queries  (async job)
          GET  /beta/security/auditLog/queries/{id}/records
Requires:  AuditLogsQuery.Read.All

The UAL contains the most comprehensive M365 activity log, covering:
  - Exchange Online (mailbox access, message read/sent/deleted)
  - SharePoint / OneDrive (file access, downloads, sharing)
  - Teams
  - Power Platform
  - Azure AD events (overlaps with directoryAudits)

The Graph beta endpoint runs as an async search job.
CIRRUS submits the query, polls for completion, then retrieves all records.

Key IOCs surfaced:
  - MailItemsAccessed by unexpected user/app (attacker reading mail)
  - Suspicious file downloads from SharePoint/OneDrive
  - Anonymous sharing links created
  - Forwarding rules set via OWA
  - Delegated mailbox access
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any

from cirrus.collectors.base import GRAPH_BETA, CollectorError, GraphCollector
from cirrus.utils.helpers import dt_to_odata

POLL_INTERVAL = 5    # seconds between status checks
POLL_TIMEOUT = 1800  # seconds before giving up — large tenants can take 20-30 min

# Map Graph API UAL field names → native Search-UnifiedAuditLog PascalCase names.
# SOF-ELK's microsoft365 pipeline expects the native field names.
_UAL_FIELD_MAP: dict[str, str] = {
    "id":                 "Id",
    "createdDateTime":    "CreationTime",
    "auditLogRecordType": "RecordType",
    "operation":          "Operation",
    "organizationId":     "OrganizationId",
    "userType":           "UserType",
    "userId":             "UserId",
    "clientIp":           "ClientIP",
    "objectId":           "ObjectId",
    "service":            "Workload",
}


class UnifiedAuditCollector(GraphCollector):
    name = "unified_audit_log"

    def collect(
        self,
        days: int = 30,
        users: list[str] | None = None,
        record_types: list[str] | None = None,
        operations: list[str] | None = None,
        start_dt: datetime | None = None,
        end_dt: datetime | None = None,
    ) -> list[dict]:
        """
        Collect Unified Audit Log records via the Graph beta async query API.

        Args:
            days:         How many days back to search (default 30, max 180).
                          Ignored when start_dt / end_dt are provided.
            users:        Filter to specific UPNs. None = all users.
            record_types: Filter to specific UAL record types
                          (e.g. ["ExchangeItem", "SharePoint"]).
            operations:   Filter to specific operations
                          (e.g. ["MailItemsAccessed", "FileDownloaded"]).
            start_dt:     Explicit collection start (UTC). Overrides days.
            end_dt:       Explicit collection end (UTC). Overrides days.

        Returns list of UAL record dicts.
        """
        if end_dt is None:
            end_dt = datetime.now(timezone.utc)
        if start_dt is None:
            start_dt = end_dt - timedelta(days=days)

        query_body: dict[str, Any] = {
            "filterStartDateTime": dt_to_odata(start_dt),
            "filterEndDateTime": dt_to_odata(end_dt),
        }

        if users:
            query_body["userPrincipalNames"] = users

        if record_types:
            query_body["recordTypeFilters"] = record_types

        if operations:
            query_body["operationFilters"] = operations

        # Submit the async query
        query_url = f"{GRAPH_BETA}/security/auditLog/queries"
        response = self._post(query_url, query_body)
        query_id = response.get("id")
        if not query_id:
            raise CollectorError("UAL query submission did not return a query ID.")

        # Poll for completion
        status_url = f"{GRAPH_BETA}/security/auditLog/queries/{query_id}"
        elapsed = 0
        while elapsed < POLL_TIMEOUT:
            status_data = self._get(status_url)
            status = status_data.get("status", "").lower()

            if status in ("succeeded", "completed"):
                break
            if status in ("failed", "cancelled"):
                raise CollectorError(
                    f"UAL query {query_id} ended with status '{status}'."
                )

            time.sleep(POLL_INTERVAL)
            elapsed += POLL_INTERVAL

        if elapsed >= POLL_TIMEOUT:
            raise CollectorError(
                f"UAL query {query_id} timed out after {POLL_TIMEOUT}s. "
                "Try a shorter date range or fewer users."
            )

        # Retrieve paginated records
        records_url = f"{GRAPH_BETA}/security/auditLog/queries/{query_id}/records"
        records = self._collect_all(records_url)
        return records

    def sofelk_transform(self, records: list[dict]) -> list[dict]:
        """
        Normalize UAL records for SOF-ELK ingestion via /logstash/microsoft365/.

        Each Graph API UAL record has:
          - Top-level camelCase fields (id, createdDateTime, operation, …)
          - An `auditData` dict containing the workload-specific payload
            with fields already in native PascalCase (ApplicationId, etc.)

        SOF-ELK expects the native Search-UnifiedAuditLog shape:
          - auditData fields promoted to top level
          - Top-level fields renamed to PascalCase (CreationTime, UserId, …)
        """
        result: list[dict] = []
        for record in records:
            normalized: dict = {}

            # 1. Promote auditData fields first (already PascalCase from the API)
            audit_data = record.get("auditData")
            if isinstance(audit_data, str):
                import json as _json
                try:
                    audit_data = _json.loads(audit_data)
                except Exception:
                    audit_data = None
            if isinstance(audit_data, dict):
                normalized.update(audit_data)

            # 2. Map and overlay top-level Graph API fields (these take precedence
            #    over any same-named keys that may have come from auditData)
            for graph_key, ual_key in _UAL_FIELD_MAP.items():
                if graph_key in record:
                    normalized[ual_key] = record[graph_key]

            result.append(normalized)
        return result
