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

# Dangerous scope combinations — each tuple (set_a, set_b, flag_name, description)
# fires when a grant contains at least one scope from set_a AND one from set_b.
# Individual HIGH_RISK_SCOPE flags are still raised; these flags add the combo context.
_DANGEROUS_COMBOS: list[tuple[frozenset, frozenset, str, str]] = [
    (
        # Can read mail + can change forwarding rules = full silent BEC exfil chain
        frozenset({"Mail.Read", "Mail.ReadWrite", "Mail.ReadBasic", "full_access_as_user"}),
        frozenset({"MailboxSettings.ReadWrite"}),
        "COMBO_MAIL_READ_AND_FORWARDING_CONTROL",
        "App can both read mail and control forwarding settings — complete silent exfil chain",
    ),
    (
        # Can read all files + can enumerate users/directory = broad data exfil
        frozenset({"Files.Read.All", "Files.ReadWrite.All"}),
        frozenset({"Directory.Read.All", "Directory.ReadWrite.All", "User.Read.All", "User.ReadWrite.All"}),
        "COMBO_FILES_AND_DIRECTORY_ACCESS",
        "App can access all files and enumerate the directory — broad data exfiltration capability",
    ),
    (
        # Can manage roles + any mail/file access = privilege escalation + exfil
        frozenset({"RoleManagement.ReadWrite.Directory"}),
        frozenset({"Mail.Read", "Mail.ReadWrite", "Files.Read.All", "Files.ReadWrite.All",
                   "Directory.ReadWrite.All", "User.ReadWrite.All"}),
        "COMBO_ROLE_MANAGEMENT_AND_DATA_ACCESS",
        "App can modify directory roles and access sensitive data — privilege escalation and exfil",
    ),
    (
        # offline_access + any mail scope = persistent silent mail access that survives password reset
        frozenset({"offline_access"}),
        frozenset({"Mail.Read", "Mail.ReadWrite", "full_access_as_user"}),
        "COMBO_PERSISTENT_MAIL_ACCESS",
        "App has persistent mail access via offline_access — survives password resets",
    ),
]


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

    # Dangerous combinations — flag when a single grant contains both risky scope groups
    for set_a, set_b, combo_flag, _ in _DANGEROUS_COMBOS:
        if scopes & set_a and scopes & set_b:
            flags.append(combo_flag)

    return flags
