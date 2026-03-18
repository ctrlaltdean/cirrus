"""
Collector: App Registrations

Endpoint: GET /applications
Requires:  Application.Read.All  (or Directory.Read.All)

App registrations are the developer-owned application objects in Entra ID.
They are distinct from service principals (/servicePrincipals), which are
the per-tenant runtime instances of an app.

During an ATO or OAuth phishing attack, adversaries may:
  - Register a new malicious app to maintain access after password resets
  - Add client secrets or certificates to an existing app to impersonate it
  - Configure the app to request broad application permissions (no user sign-in
    required — these permissions work silently in the background)
  - Set reply URLs pointing to attacker-controlled infrastructure

Difference from ServicePrincipalsCollector:
  - /applications shows apps CREATED in this tenant (first-party registrations)
  - /servicePrincipals shows apps CONSENTED TO in this tenant (first + third party)
  For ATO, new app registrations are a persistence mechanism — flag them.

Key IOCs:
  - App created during or shortly after the suspected access window
  - App with application permissions (type=Role) — works without user sign-in
  - Multi-tenant app (signInAudience allows external tenants)
  - App with client secrets or certificates configured
  - Localhost or suspicious redirect URIs
  - No verified publisher
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cirrus.collectors.base import GRAPH_BASE, GraphCollector
from cirrus.utils.helpers import dt_to_odata

_APP_SELECT = (
    "id,appId,displayName,createdDateTime,signInAudience,"
    "web,publicClient,keyCredentials,passwordCredentials,"
    "requiredResourceAccess,publisherDomain,verifiedPublisher,tags"
)

# signInAudience values that allow external tenants — higher risk
_MULTI_TENANT_AUDIENCES = frozenset({
    "AzureADMultipleOrgs",
    "AzureADandPersonalMicrosoftAccount",
    "PersonalMicrosoftAccount",
})


def _flag_app(app: dict, start_dt: datetime | None) -> list[str]:
    """
    Return IOC flag strings for an app registration record.

    Args:
        app:      The application dict from the Graph API.
        start_dt: Collection window start. Apps created on or after this date
                  receive a RECENTLY_CREATED flag. Falls back to 30 days ago
                  if None.
    """
    flags: list[str] = []

    # Threshold for "recently created"
    if start_dt is None:
        threshold = datetime.now(timezone.utc) - timedelta(days=30)
    else:
        threshold = start_dt

    # ── Recently created ──────────────────────────────────────────────────────
    created_str = app.get("createdDateTime") or ""
    if created_str:
        try:
            created_dt = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
            if created_dt >= threshold:
                flags.append(f"RECENTLY_CREATED:{created_str[:10]}")
        except ValueError:
            pass

    # ── No verified publisher ─────────────────────────────────────────────────
    if not app.get("verifiedPublisher"):
        flags.append("NO_VERIFIED_PUBLISHER")

    # ── Multi-tenant ──────────────────────────────────────────────────────────
    audience = app.get("signInAudience") or ""
    if audience in _MULTI_TENANT_AUDIENCES:
        flags.append(f"MULTI_TENANT:{audience}")

    # ── Application permissions (type=Role) ───────────────────────────────────
    # Application permissions work without a signed-in user — the app can
    # silently access data across the entire tenant using its own credentials.
    # This is a significant escalation over delegated (Scope) permissions.
    has_app_perms = False
    for resource in app.get("requiredResourceAccess") or []:
        for access in resource.get("resourceAccess") or []:
            if access.get("type") == "Role":
                has_app_perms = True
                break
        if has_app_perms:
            break
    if has_app_perms:
        flags.append("HAS_APP_PERMISSIONS")

    # ── Client credentials (secrets / certificates) ───────────────────────────
    pw_creds = app.get("passwordCredentials") or []
    key_creds = app.get("keyCredentials") or []
    if pw_creds:
        flags.append(f"HAS_CLIENT_SECRETS:{len(pw_creds)}")
    if key_creds:
        flags.append(f"HAS_CERTIFICATES:{len(key_creds)}")

    # ── Redirect URIs — localhost or suspicious patterns ──────────────────────
    web = app.get("web") or {}
    redirect_uris = web.get("redirectUris") or []
    public_client = app.get("publicClient") or {}
    redirect_uris += public_client.get("redirectUris") or []

    for uri in redirect_uris:
        uri_lower = uri.lower()
        if "localhost" in uri_lower or "127.0.0.1" in uri_lower:
            flags.append(f"LOCALHOST_REDIRECT:{uri}")
        elif uri_lower.startswith("http://") and "localhost" not in uri_lower:
            # Non-TLS redirect to a real host — uncommon in production
            flags.append(f"PLAINTEXT_REDIRECT:{uri}")

    return flags


class AppRegistrationsCollector(GraphCollector):
    name = "app_registrations"

    def collect(
        self,
        start_dt: datetime | None = None,
        end_dt: datetime | None = None,
    ) -> list[dict]:
        """
        Collect app registrations from the tenant.

        When start_dt is provided, returns only apps created on or after
        that date — scoping collection to the investigation window. Without
        start_dt, returns all app registrations.

        All records are annotated with _iocFlags regardless of date filter.
        Apps created after start_dt (or within the last 30 days if start_dt
        is None) receive a RECENTLY_CREATED flag.

        Args:
            start_dt: Collection window start. Filters results to apps
                      created on or after this date, and sets the
                      RECENTLY_CREATED flag threshold.
            end_dt:   Collection window end. Adds an upper creation date
                      bound when start_dt is also provided.

        Returns list of application dicts, each with an _iocFlags list.
        """
        params: dict = {
            "$select": _APP_SELECT,
            "$top": 999,
        }

        if start_dt is not None:
            filters = [f"createdDateTime ge {dt_to_odata(start_dt)}"]
            if end_dt is not None:
                filters.append(f"createdDateTime le {dt_to_odata(end_dt)}")
            params["$filter"] = " and ".join(filters)
            params["$count"] = "true"

        records = self._collect_all(f"{GRAPH_BASE}/applications", params)

        for app in records:
            app["_iocFlags"] = _flag_app(app, start_dt)

        return records
