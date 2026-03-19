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
