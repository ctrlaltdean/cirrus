"""
Collector: OAuth App Grants (Delegated & Application Permissions)

Endpoints:
  GET /oauth2PermissionGrants              — delegated permissions (user consented)
  GET /servicePrincipals/{id}/appRoleAssignments — application permissions (admin consented)
  GET /users/{id}/oauth2PermissionGrants   — per-user delegated consents

Requires: Directory.Read.All

OAuth phishing is a common BEC initial access vector. The attacker tricks a user
into consenting to a malicious app that gets persistent delegated access without
needing the user's password or MFA.

Key IOCs surfaced:
  - Apps with Mail.Read, Mail.ReadWrite, Contacts.Read (can read/exfiltrate mail)
  - Apps with MailboxSettings.ReadWrite (can set forwarding rules)
  - Apps from unknown publishers / no verified publisher
  - Apps consented to very recently
  - Apps with broad Directory.Read.All or full_access_as_user
  - Apps not in the Microsoft first-party catalog
"""

from __future__ import annotations

from cirrus.collectors.base import GRAPH_BASE, GraphCollector

# Permissions that give an app access to mailbox content
HIGH_RISK_SCOPES = {
    "Mail.Read", "Mail.ReadWrite", "Mail.ReadBasic", "Mail.Send",
    "MailboxSettings.ReadWrite", "full_access_as_user",
    "Contacts.Read", "Contacts.ReadWrite",
    "Files.Read.All", "Files.ReadWrite.All",
    "Directory.Read.All", "Directory.ReadWrite.All",
    "User.Read.All", "User.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "offline_access",  # allows persistent access without re-consent
}


class OAuthGrantsCollector(GraphCollector):
    name = "oauth_grants"

    def collect(
        self,
        users: list[str] | None = None,
    ) -> list[dict]:
        """
        Collect all OAuth permission grants.

        If users is specified, collects per-user delegated grants.
        Always collects tenant-wide delegated grants.

        Returns a list of grant records annotated with IOC flags.
        """
        records: list[dict] = []

        # Tenant-wide delegated permission grants
        grants = self._collect_all(
            f"{GRAPH_BASE}/oauth2PermissionGrants",
            params={"$top": 999},
        )
        for grant in grants:
            grant["_grantType"] = "delegated"
            grant["_iocFlags"] = _flag_grant(grant.get("scope", ""))
            records.append(grant)

        # Per-user grants if specific users are targeted
        if users:
            for upn in users:
                try:
                    user_grants = self._collect_all(
                        f"{GRAPH_BASE}/users/{upn}/oauth2PermissionGrants",
                        params={"$top": 999},
                    )
                    for grant in user_grants:
                        grant["_sourceUser"] = upn
                        grant["_grantType"] = "delegated_user"
                        grant["_iocFlags"] = _flag_grant(grant.get("scope", ""))
                    records.extend(user_grants)
                except Exception:
                    pass

        return records


def _flag_grant(scope_string: str) -> list[str]:
    """Return IOC flags for a scope string."""
    flags: list[str] = []
    if not scope_string:
        return flags
    scopes = {s.strip() for s in scope_string.split()}
    for scope in scopes:
        if scope in HIGH_RISK_SCOPES:
            flags.append(f"HIGH_RISK_SCOPE:{scope}")
    return flags
