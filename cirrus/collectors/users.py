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
  - Guest accounts (userType == "Guest") — often over-permissioned
  - Disabled accounts that are still authenticating (caught by sign-in logs)
  - Accounts with no assigned licenses (service accounts, orphaned accounts)
  - External identity providers linked to the account (non-Azure AD federation)
  - Accounts with no on-premises anchor (cloud-only, harder to trace)
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from cirrus.collectors.base import GRAPH_BASE, GraphCollector
from cirrus.utils.helpers import days_ago_filter


# Identity providers that indicate the account is not a standard Entra ID
# account — could be a B2B / social login / external IdP linkage.
_EXTERNAL_IDENTITY_PROVIDERS = frozenset({
    "google.com",
    "facebook.com",
    "emailAddress",  # OTP-only accounts, no password
    "externalAzureAD",
})


def _flag_user(user: dict, start_dt: datetime | None) -> list[str]:
    """
    Return IOC flag strings for a single user record.

    Args:
        user:     The user dict from Graph API.
        start_dt: Collection window start. Users created on or after this
                  date receive a RECENTLY_CREATED flag.
    """
    flags: list[str] = []

    # ── Recently created account ───────────────────────────────────────────
    # New accounts created during or just before an incident window are a
    # classic attacker persistence technique — create a backdoor user.
    created_str = user.get("createdDateTime") or ""
    if created_str and start_dt is not None:
        try:
            created_dt = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
            if created_dt >= start_dt:
                flags.append(f"RECENTLY_CREATED:{created_str[:10]}")
        except ValueError:
            pass

    # ── Guest account ──────────────────────────────────────────────────────
    # Guest accounts (B2B invites) with high permissions are a common
    # persistence mechanism — attacker invites an external account they control.
    if (user.get("userType") or "").lower() == "guest":
        flags.append("GUEST_ACCOUNT")

    # ── Disabled account ───────────────────────────────────────────────────
    # A disabled account that appears in sign-in logs is suspicious —
    # it may have been disabled as part of IR but then re-enabled by attacker.
    if not user.get("accountEnabled", True):
        flags.append("ACCOUNT_DISABLED")

    # ── No assigned licenses ───────────────────────────────────────────────
    # Unlicensed accounts are often service accounts or orphaned accounts.
    # Attackers sometimes create unlicensed accounts to avoid attention in
    # license management tools.
    assigned_licenses = user.get("assignedLicenses") or []
    if not assigned_licenses:
        flags.append("NO_ASSIGNED_LICENSES")

    # ── External identity provider ─────────────────────────────────────────
    # Accounts federated to external IdPs (Google, Facebook, external Azure AD)
    # or email OTP accounts indicate non-standard authentication paths that
    # may bypass Conditional Access policies targeting Entra ID accounts.
    identities = user.get("identities") or []
    for identity in identities:
        issuer = (identity.get("issuer") or "").lower()
        sign_in_type = identity.get("signInType") or ""
        if sign_in_type in _EXTERNAL_IDENTITY_PROVIDERS or issuer in _EXTERNAL_IDENTITY_PROVIDERS:
            flags.append(f"EXTERNAL_IDENTITY:{sign_in_type or issuer}")
            break
        # Catch any non-federated, non-standard issuer (not the tenant domain)
        # by checking if sign-in type is "federated" — value is third-party IdP
        if sign_in_type == "federated" and issuer:
            flags.append(f"EXTERNAL_IDENTITY:federated:{issuer}")
            break

    return flags


class UsersCollector(GraphCollector):
    name = "users"

    def collect(
        self,
        days: int | None = None,
        users: list[str] | None = None,
        start_dt: datetime | None = None,
    ) -> list[dict]:
        """
        Collect user directory records, annotating each with IOC flags.

        Args:
            days:     If set, filter to users created in the last N days.
            users:    If set, collect only these specific UPNs.
            start_dt: Collection window start. Users created on or after
                      this date receive a RECENTLY_CREATED flag.

        Returns list of user dicts, each with _iocFlags.
        """
        if users:
            records: list[dict] = []
            for upn in users:
                try:
                    user = self._get(
                        f"{GRAPH_BASE}/users/{upn}",
                        params={"$select": _USER_SELECT},
                    )
                    user["_iocFlags"] = _flag_user(user, start_dt)
                    records.append(user)
                except Exception as e:
                    records.append({
                        "_requestedUser": upn,
                        "_error": str(e),
                        "_iocFlags": [],
                    })
            return records

        params: dict[str, Any] = {
            "$select": _USER_SELECT,
            "$top": 999,
        }

        if days is not None:
            since = days_ago_filter(days)
            params["$filter"] = f"createdDateTime ge {since}"
            params["$count"] = "true"  # createdDateTime requires advanced query support

        records = self._collect_all(f"{GRAPH_BASE}/users", params)
        for user in records:
            user["_iocFlags"] = _flag_user(user, start_dt)
        return records


_USER_SELECT = (
    "id,displayName,userPrincipalName,mail,userType,accountEnabled,"
    "createdDateTime,lastPasswordChangeDateTime,onPremisesLastSyncDateTime,"
    "onPremisesImmutableId,onPremisesSyncEnabled,assignedLicenses,"
    "jobTitle,department,officeLocation,city,country,usageLocation,"
    "proxyAddresses,otherMails,identities"
)
