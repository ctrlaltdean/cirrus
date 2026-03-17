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

POLL_INTERVAL = 5    # seconds between status checks
POLL_TIMEOUT = 1800  # seconds before giving up — large tenants can take 20-30 min


class UnifiedAuditCollector(GraphCollector):
    name = "unified_audit_log"

    def collect(
        self,
        days: int = 30,
        users: list[str] | None = None,
        record_types: list[str] | None = None,
        operations: list[str] | None = None,
    ) -> list[dict]:
        """
        Collect Unified Audit Log records via the Graph beta async query API.

        Args:
            days:         How many days back to search (default 30, max 180).
            users:        Filter to specific UPNs. None = all users.
            record_types: Filter to specific UAL record types
                          (e.g. ["ExchangeItem", "SharePoint"]).
            operations:   Filter to specific operations
                          (e.g. ["MailItemsAccessed", "FileDownloaded"]).

        Returns list of UAL record dicts.
        """
        self._require_license(
            "advanced_auditing",
            "The Unified Audit Log endpoint requires M365 Advanced Auditing "
            "(Microsoft 365 E5 or the Purview Audit Premium add-on).",
        )

        end_dt = datetime.now(timezone.utc)
        start_dt = end_dt - timedelta(days=days)

        query_body: dict[str, Any] = {
            "filterStartDateTime": start_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "filterEndDateTime": end_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
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
