"""
MSAL-based authentication for Microsoft Graph API.

Supports interactive browser login with per-tenant token caching.
Multi-tenant: each tenant gets its own cached token set.
App registration override is on the roadmap via --client-id flag.
"""

from __future__ import annotations

import json
from pathlib import Path

import msal

from cirrus.auth.private_browser import private_browser_auth

# Default: Microsoft Graph Command Line Tools (pre-registered, broad delegated perms)
DEFAULT_CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"

# All scopes needed across all collectors.
# Analysts must have appropriate roles (Global Reader, Security Reader, etc.)
GRAPH_SCOPES = [
    "https://graph.microsoft.com/AuditLog.Read.All",
    "https://graph.microsoft.com/Directory.Read.All",
    "https://graph.microsoft.com/Policy.Read.All",
    "https://graph.microsoft.com/MailboxSettings.Read",
    "https://graph.microsoft.com/Calendars.Read",
    "https://graph.microsoft.com/User.Read.All",
    "https://graph.microsoft.com/IdentityRiskyUser.Read.All",
    "https://graph.microsoft.com/IdentityRiskEvent.Read.All",
    "https://graph.microsoft.com/UserAuthenticationMethod.Read.All",
    "https://graph.microsoft.com/AuditLogsQuery.Read.All",
    "https://graph.microsoft.com/SecurityEvents.Read.All",
    # Required for compliance audit checks
    "https://graph.microsoft.com/Reports.Read.All",
    "https://graph.microsoft.com/RoleManagement.Read.Directory",
]

# Scopes that require admin consent and are commonly missing when the analyst
# authenticated before admin consent was granted. Used by check_token_scopes()
# to produce actionable warnings rather than silent 403s later.
_ADMIN_CONSENT_SCOPES = frozenset({
    "AuditLog.Read.All",
    "AuditLogsQuery.Read.All",
    "IdentityRiskyUser.Read.All",
    "IdentityRiskEvent.Read.All",
    "UserAuthenticationMethod.Read.All",
    "Calendars.Read",
    "MailboxSettings.Read",
    "Reports.Read.All",
    "RoleManagement.Read.Directory",
})

# Exchange Online scope — used to obtain a token for Connect-ExchangeOnline
# -AccessToken so the EXO PowerShell session reuses the existing MSAL auth
# rather than opening a second browser prompt.
EXO_SCOPES = ["https://outlook.office365.com/Exchange.Manage"]

CACHE_DIR = Path.home() / ".cirrus"
CACHE_FILE = CACHE_DIR / "token_cache.json"


def _load_cache() -> msal.SerializableTokenCache:
    cache = msal.SerializableTokenCache()
    if CACHE_FILE.exists():
        cache.deserialize(CACHE_FILE.read_text())
    return cache


def _save_cache(cache: msal.SerializableTokenCache) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    if cache.has_state_changed:
        CACHE_FILE.write_text(cache.serialize())


def _build_app(tenant_id: str, client_id: str, cache: msal.SerializableTokenCache) -> msal.PublicClientApplication:
    authority = f"https://login.microsoftonline.com/{tenant_id}"
    return msal.PublicClientApplication(
        client_id=client_id,
        authority=authority,
        token_cache=cache,
    )


def check_token_scopes(access_token: str) -> list[str]:
    """
    Decode the JWT access token and return a list of admin-consent scopes that
    are present in GRAPH_SCOPES but absent from the token's scp claim.

    This catches the common case where the analyst authenticated before admin
    consent was granted — the token is valid but silently missing scopes, which
    only surfaces as a 403 when the affected collector runs.

    Returns a list of missing scope short-names (e.g. ["AuditLog.Read.All"]).
    Returns an empty list if all required admin-consent scopes are present or
    if the token cannot be decoded.
    """
    import base64
    import json as _json

    try:
        # JWT is header.payload.signature — decode the payload only
        payload_b64 = access_token.split(".")[1]
        # Pad to a multiple of 4 for standard base64
        payload_b64 += "=" * (4 - len(payload_b64) % 4)
        payload = _json.loads(base64.urlsafe_b64decode(payload_b64))
    except Exception:
        return []  # can't decode — don't block the flow

    # scp is space-separated for delegated tokens; roles is a list for app tokens
    granted = set((payload.get("scp") or "").split())
    return sorted(_ADMIN_CONSENT_SCOPES - granted)


def get_token(tenant_id: str, client_id: str = DEFAULT_CLIENT_ID, force_refresh: bool = False) -> str:
    """
    Return a valid access token for the given tenant.

    Tries the cache first. If nothing is cached or force_refresh is set,
    launches an interactive browser login.

    Returns the raw access token string.
    """
    cache = _load_cache()
    app = _build_app(tenant_id, client_id, cache)

    result = None

    if not force_refresh:
        accounts = app.get_accounts()
        if accounts:
            result = app.acquire_token_silent(GRAPH_SCOPES, account=accounts[0])

    if not result:
        with private_browser_auth():
            result = app.acquire_token_interactive(
                scopes=GRAPH_SCOPES,
                prompt="select_account",
            )

    _save_cache(cache)

    if "access_token" not in result:
        error = result.get("error", "unknown_error")
        desc = result.get("error_description", "No description available.")
        raise AuthenticationError(f"Authentication failed [{error}]: {desc}")

    return result["access_token"]


def get_token_device_code(tenant_id: str, client_id: str = DEFAULT_CLIENT_ID) -> str:
    """
    Authenticate via device code flow (headless/no-browser environments).
    Prints the device code URL and code for the analyst to complete on another device.
    """
    cache = _load_cache()
    app = _build_app(tenant_id, client_id, cache)

    flow = app.initiate_device_flow(scopes=GRAPH_SCOPES)
    if "user_code" not in flow:
        raise AuthenticationError("Failed to initiate device code flow.")

    print(flow["message"])  # MSAL prints the URL and code

    result = app.acquire_token_by_device_flow(flow)
    _save_cache(cache)

    if "access_token" not in result:
        error = result.get("error", "unknown_error")
        desc = result.get("error_description", "No description available.")
        raise AuthenticationError(f"Device code auth failed [{error}]: {desc}")

    return result["access_token"]


def get_token_silent(tenant_id: str, client_id: str = DEFAULT_CLIENT_ID) -> str | None:
    """
    Return a cached access token without prompting for browser login.
    Returns None if no valid cached token exists.
    """
    cache = _load_cache()
    app = _build_app(tenant_id, client_id, cache)
    accounts = app.get_accounts()
    if not accounts:
        return None
    result = app.acquire_token_silent(GRAPH_SCOPES, account=accounts[0])
    _save_cache(cache)
    if result and "access_token" in result:
        return result["access_token"]
    return None


def get_exo_token_silent(tenant_id: str, client_id: str = DEFAULT_CLIENT_ID) -> str | None:
    """
    Try to acquire an Exchange Online access token silently using the existing
    MSAL token cache (same account/refresh token as the Graph session).

    If successful, the caller can pass this token to Connect-ExchangeOnline
    -AccessToken to avoid a second browser prompt.

    Returns the token string, or None if silent acquisition fails (e.g. the
    app hasn't been granted Exchange.Manage permission in this tenant).  The
    caller should fall back to letting Connect-ExchangeOnline handle auth
    interactively when None is returned.
    """
    cache = _load_cache()
    app = _build_app(tenant_id, client_id, cache)
    accounts = app.get_accounts()
    if not accounts:
        return None
    result = app.acquire_token_silent(EXO_SCOPES, account=accounts[0])
    _save_cache(cache)
    if result and "access_token" in result:
        return result["access_token"]
    return None


def lookup_service_principal(token: str, client_id: str) -> dict | None:
    """
    Look up the service principal for client_id in the authenticated tenant.
    Uses Directory.Read.All (already in GRAPH_SCOPES).
    Returns a dict with 'id', 'displayName', 'appId', or None if not found.
    """
    import requests as _requests
    url = (
        "https://graph.microsoft.com/v1.0/servicePrincipals"
        f"?$filter=appId eq '{client_id}'&$select=id,displayName,appId"
    )
    try:
        resp = _requests.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=15,
        )
        if resp.status_code != 200:
            return None
        items = resp.json().get("value", [])
        return items[0] if items else None
    except Exception:
        return None


def logout(tenant_id: str, client_id: str = DEFAULT_CLIENT_ID) -> int:
    """
    Remove all cached accounts for a tenant.
    Returns the number of accounts removed.
    """
    cache = _load_cache()
    app = _build_app(tenant_id, client_id, cache)
    accounts = app.get_accounts()
    count = 0
    for account in accounts:
        app.remove_account(account)
        count += 1
    _save_cache(cache)
    return count


def list_cached_tenants() -> list[dict]:
    """
    Return a list of tenants/accounts currently in the token cache.
    """
    if not CACHE_FILE.exists():
        return []
    try:
        data = json.loads(CACHE_FILE.read_text())
        accounts = data.get("Account", {})
        result = []
        for key, acct in accounts.items():
            result.append({
                "username": acct.get("username", "unknown"),
                "tenant_id": acct.get("realm", "unknown"),
                "environment": acct.get("environment", "unknown"),
            })
        return result
    except Exception:
        return []


class AuthenticationError(Exception):
    """Raised when MSAL authentication fails."""
    pass
