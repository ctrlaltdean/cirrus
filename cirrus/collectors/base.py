"""
Base collector class.

All collectors inherit from GraphCollector. It handles:
  - Authenticated HTTP requests (requests session with bearer token)
  - Automatic pagination via @odata.nextLink
  - Rate-limit handling (HTTP 429 with Retry-After)
  - Transient error retries (500, 503) with exponential backoff
  - Structured error reporting
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any, Callable, Iterator

import requests

if TYPE_CHECKING:
    from cirrus.utils.license import TenantLicenseProfile

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"

MAX_RETRIES = 5
BACKOFF_BASE = 2  # seconds

# Entra ID P2 service plan ID — required for Identity Protection endpoints
_P2_SERVICE_PLAN_ID = "eec0eb4f-6444-4f95-aba0-50c24d67f998"


class CollectorError(Exception):
    """Raised when a collection cannot be completed."""
    pass


class GraphCollector:
    """
    Base class for all Microsoft Graph API collectors.

    Subclasses implement `collect()` which returns a list of records.
    """

    #: Human-readable name used in logs and progress display
    name: str = "base"

    def __init__(self, token: str) -> None:
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
                "ConsistencyLevel": "eventual",  # needed for $count and advanced filters
            }
        )
        #: Pre-fetched license profile. Set by the workflow before collection
        #: starts. If None, _require_license() performs a lazy fetch on first use.
        self.license_profile: TenantLicenseProfile | None = None

        #: Optional status callback. When set by the workflow, the collector
        #: calls this with short human-readable status strings so the progress
        #: display can update in real time (e.g. during UAL polling).
        self.on_status: Callable[[str], None] | None = None

        #: Optional page callback. When set by the workflow, _collect_all
        #: calls this with each raw page of records as they arrive so the
        #: workflow can stream them to disk without waiting for full collection.
        self.on_page: Callable[[list[dict]], None] | None = None

    # ------------------------------------------------------------------
    # Low-level HTTP helpers
    # ------------------------------------------------------------------

    def _get(self, url: str, params: dict | None = None) -> dict:
        """GET a Graph API URL, handling retries and rate limiting."""
        for attempt in range(1, MAX_RETRIES + 1):
            resp = self.session.get(url, params=params, timeout=60)

            if resp.status_code == 429:
                retry_after = int(resp.headers.get("Retry-After", BACKOFF_BASE * attempt))
                time.sleep(retry_after)
                continue

            if resp.status_code in (500, 502, 503, 504):
                wait = BACKOFF_BASE ** attempt
                time.sleep(wait)
                continue

            if resp.status_code == 401:
                raise CollectorError(
                    "HTTP 401: Access token expired or insufficient permissions. "
                    "Re-authenticate with `cirrus auth login`."
                )

            if resp.status_code == 403:
                raise CollectorError(
                    f"HTTP 403: Permission denied at {url}. "
                    "Ensure the analyst account has the required roles "
                    "(Global Reader, Security Reader, or equivalent)."
                )

            if resp.status_code == 404:
                raise CollectorError(f"HTTP 404: Resource not found: {url}")

            if resp.status_code == 400:
                try:
                    detail = resp.json().get("error", {}).get("message", resp.text[:300])
                except Exception:
                    detail = resp.text[:300]
                raise CollectorError(f"HTTP 400: Bad request to {url} — {detail}")

            try:
                resp.raise_for_status()
            except Exception as http_err:
                raise CollectorError(f"HTTP {resp.status_code}: {url} — {http_err}") from http_err

            return resp.json()

        raise CollectorError(f"Failed after {MAX_RETRIES} retries: {url}")

    def _post(self, url: str, body: dict) -> dict:
        """POST to a Graph API URL, handling retries and rate limiting."""
        for attempt in range(1, MAX_RETRIES + 1):
            resp = self.session.post(url, json=body, timeout=60)

            if resp.status_code == 429:
                retry_after = int(resp.headers.get("Retry-After", BACKOFF_BASE * attempt))
                time.sleep(retry_after)
                continue

            if resp.status_code in (500, 502, 503, 504):
                wait = BACKOFF_BASE ** attempt
                time.sleep(wait)
                continue

            if resp.status_code == 401:
                raise CollectorError("HTTP 401: Access token expired.")

            if resp.status_code == 403:
                raise CollectorError(f"HTTP 403: Permission denied at {url}.")

            if resp.status_code == 400:
                try:
                    detail = resp.json().get("error", {}).get("message", resp.text[:300])
                except Exception:
                    detail = resp.text[:300]
                raise CollectorError(f"HTTP 400: Bad request to {url} — {detail}")

            try:
                resp.raise_for_status()
            except Exception as http_err:
                raise CollectorError(f"HTTP {resp.status_code}: {url} — {http_err}") from http_err

            return resp.json()

        raise CollectorError(f"POST failed after {MAX_RETRIES} retries: {url}")

    def _paginate(self, url: str, params: dict | None = None) -> Iterator[dict]:
        """
        Yield every page of results from a Graph API endpoint.
        Follows @odata.nextLink automatically.
        """
        next_url: str | None = url
        first = True
        while next_url:
            data = self._get(next_url, params=params if first else None)
            first = False
            yield data
            next_url = data.get("@odata.nextLink")

    def _collect_all(self, url: str, params: dict | None = None) -> list[dict]:
        """
        Return all records from a paginated Graph API endpoint.
        Each page may return a 'value' list.

        Fires callbacks for each page if set:
          on_page(page_records)  — raw records, for streaming to disk
          on_status(msg)         — human-readable running count for the UI
        """
        records: list[dict] = []
        for page in self._paginate(url, params):
            page_records = page.get("value", [])
            records.extend(page_records)
            if self.on_page and page_records:
                self.on_page(page_records)
            if self.on_status and records:
                self.on_status(f"retrieving records... ({len(records)} so far)")
        return records

    def _require_license(self, feature: str, detail: str) -> None:
        """
        Raise CollectorError if *feature* is not licensed on the tenant.

        Uses a pre-fetched TenantLicenseProfile when available (set by the
        workflow orchestrator), otherwise performs a lazy fetch and caches it.

        Args:
            feature: One of "p1", "p2", "exchange", "advanced_auditing".
            detail:  Human-readable message used in the CollectorError.
        """
        from cirrus.utils.license import TenantLicenseProfile

        if self.license_profile is None:
            self.license_profile = TenantLicenseProfile.fetch(self.session)

        if not self.license_profile.allows(feature):
            raise CollectorError(f"Skipped: {detail}")

    def sofelk_transform(self, records: list[dict]) -> list[dict]:
        """
        Transform records into SOF-ELK compatible NDJSON format.

        The default implementation is a passthrough — records are written
        as-is to the .ndjson file. Subclasses override this to normalize
        field names, promote nested structures, etc.

        Args:
            records: Raw records returned by collect().

        Returns:
            List of dicts to write to the .ndjson output file.
        """
        return records

    def collect(self, **kwargs: Any) -> list[dict]:
        """
        Override in subclasses. Returns a list of record dicts.
        """
        raise NotImplementedError
