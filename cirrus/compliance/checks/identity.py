"""
CIS Compliance Checks — Section 1: Identity & Access Management

Covers: Security Defaults, MFA, Conditional Access, Legacy Auth,
        App Consent, Guest Access.

Sources: CIS Microsoft 365 Foundations Benchmark v3.1
         CIS Microsoft Azure Foundations Benchmark v2.0 (Entra section)
"""

from __future__ import annotations

from cirrus.compliance.base import BaseCheck, CheckResult, CheckStatus, ManualCheck
from cirrus.compliance.context import PolicyContext

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ca_enabled(policy: dict) -> bool:
    return policy.get("state", "").lower() == "enabled"


def _ca_requires_mfa(policy: dict) -> bool:
    grant = policy.get("grantControls") or {}
    built_in = [c.lower() for c in (grant.get("builtInControls") or [])]
    return "mfa" in built_in


def _ca_includes_all_users(policy: dict) -> bool:
    users = (policy.get("conditions") or {}).get("users") or {}
    include = users.get("includeUsers", [])
    return "All" in include


def _ca_blocks_legacy_auth(policy: dict) -> bool:
    conditions = policy.get("conditions") or {}
    client_app_types = conditions.get("clientAppTypes") or []
    types_lower = [t.lower() for t in client_app_types]
    has_legacy = "exchangeactivesync" in types_lower or "other" in types_lower
    grant = policy.get("grantControls") or {}
    is_block = grant.get("operator", "").lower() == "block" or (
        not grant.get("builtInControls") and not grant.get("customAuthenticationFactors")
    )
    # 'block' in CA is represented as grantControls being null or having 'Block'
    block_controls = [c.lower() for c in (grant.get("builtInControls") or [])]
    is_block = "block" in block_controls or grant is None
    return has_legacy and is_block


def _ca_includes_admin_roles(policy: dict) -> bool:
    users = (policy.get("conditions") or {}).get("users") or {}
    include_roles = users.get("includeRoles", [])
    # Common privileged role template IDs
    admin_roles = {
        "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
        "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",  # SharePoint Administrator
        "29232cdf-9323-42fd-ade2-1d097af3e4de",  # Exchange Administrator
        "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",  # Conditional Access Administrator
        "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
        "69091246-20e8-4a56-aa4d-066075b2a7a8",  # Teams Administrator
        "9360feb5-f418-4baa-8175-e2a00bac4301",  # Directory Writers
    }
    return "All" in include_roles or bool(set(include_roles) & admin_roles)


def _security_defaults_enabled(ctx: PolicyContext) -> bool:
    return ctx.security_defaults.get("isEnabled", False)


# ---------------------------------------------------------------------------
# 1.1 — Security Defaults & Modern Authentication
# ---------------------------------------------------------------------------

class CheckSecurityDefaults(BaseCheck):
    """
    M365-1.1.1 / Entra-1.1.1
    Security Defaults state vs. Conditional Access usage.

    If CA policies are in use, Security Defaults should be DISABLED
    (they conflict). If no CA policies are configured, Security Defaults
    should be ENABLED as a baseline.
    """
    control_id = "M365-1.1.1"
    title = "Security Defaults vs. Conditional Access"
    benchmark = "CIS M365 & Entra"
    level = 1
    section = "1 - Identity & Access Management"
    rationale = (
        "Security Defaults provide basic MFA and legacy auth protections. "
        "When Conditional Access is used, Security Defaults must be disabled "
        "to prevent conflicts. If neither is in use, there is no MFA protection."
    )
    remediation = (
        "If using Conditional Access: disable Security Defaults in "
        "Entra ID > Properties > Manage Security Defaults. "
        "If NOT using CA: enable Security Defaults as a minimum baseline."
    )
    reference = "CIS M365 v3.1 §1.1.1 | CIS Entra v2.0 §1.1"

    def run(self, ctx: PolicyContext) -> CheckResult:
        sd_enabled = _security_defaults_enabled(ctx)
        ca_count = len([p for p in ctx.ca_policies if _ca_enabled(p)])

        if sd_enabled and ca_count > 0:
            return self._result(
                CheckStatus.FAIL,
                expected="Security Defaults disabled when CA policies are active",
                actual=f"Security Defaults ENABLED with {ca_count} active CA policies",
                notes="Security Defaults and Conditional Access cannot coexist. CA policies may not enforce correctly.",
            )
        elif not sd_enabled and ca_count == 0:
            return self._result(
                CheckStatus.FAIL,
                expected="Either Security Defaults enabled, or CA policies configured",
                actual="Security Defaults DISABLED and no active CA policies found",
                notes="No baseline MFA protection is in place.",
            )
        elif sd_enabled and ca_count == 0:
            return self._result(
                CheckStatus.WARN,
                expected="Conditional Access policies (preferred) or Security Defaults",
                actual="Security Defaults ENABLED, no CA policies",
                notes="Security Defaults is acceptable but CA policies offer more granular control.",
            )
        else:
            return self._result(
                CheckStatus.PASS,
                expected="Security Defaults disabled, CA policies active",
                actual=f"Security Defaults DISABLED, {ca_count} active CA policies",
            )


class CheckModernAuthExchange(BaseCheck):
    """
    M365-1.1.2  Modern Authentication enabled for Exchange Online.
    Automated: uses OAuth2ClientProfileEnabled from Exchange Online org config (PS batch).
    Fallback: MANUAL instructions.
    """
    control_id = "M365-1.1.2"
    title = "Modern Authentication enabled for Exchange Online"
    benchmark = "CIS M365"
    level = 1
    section = "1 - Identity & Access Management"
    expected = "OAuth2ClientProfileEnabled = True (modern auth on)"
    rationale = "Legacy Basic Auth for Exchange allows credential stuffing and bypasses MFA."
    remediation = "Run: Set-OrganizationConfig -OAuth2ClientProfileEnabled $true"
    manual_steps = (
        "In Exchange Online PowerShell:\n"
        "  1. Connect-ExchangeOnline\n"
        "  2. Get-OrganizationConfig | Select-Object OAuth2ClientProfileEnabled\n"
        "  Expected: True\n\n"
        "Or via Microsoft 365 Admin Center:\n"
        "  Settings > Org Settings > Modern Authentication"
    )
    reference = "CIS M365 v3.1 §1.1.2"

    def run(self, ctx: PolicyContext) -> CheckResult:
        ps = ctx.exchange_ps
        if not ps or not ps.available:
            ps_error = ps.error if ps else "Exchange PS not run"
            return self._result(
                CheckStatus.MANUAL,
                actual=f"Exchange Online PS unavailable: {ps_error}",
                notes=self.manual_steps,
            )

        org_config = ps.org_config
        if not org_config:
            return self._result(
                CheckStatus.MANUAL,
                actual="Org config not returned from PS — verify manually",
                notes=self.manual_steps,
            )

        modern_auth = org_config.get("OAuth2ClientProfileEnabled")
        if modern_auth is True:
            return self._result(
                CheckStatus.PASS,
                actual="OAuth2ClientProfileEnabled = True — modern authentication is enabled",
            )
        if modern_auth is False:
            return self._result(
                CheckStatus.FAIL,
                actual="OAuth2ClientProfileEnabled = False — legacy auth is in use",
            )

        return self._result(
            CheckStatus.MANUAL,
            actual="OAuth2ClientProfileEnabled state unknown — verify manually",
            notes=self.manual_steps,
        )


# ---------------------------------------------------------------------------
# 1.2 — Multi-Factor Authentication
# ---------------------------------------------------------------------------

class CheckMFAAllUsers(BaseCheck):
    """
    M365-1.2.1 / Entra-1.2.1
    Ensure MFA is required for all users (via CA or Security Defaults).
    """
    control_id = "M365-1.2.1"
    title = "MFA required for all users"
    benchmark = "CIS M365 & Entra"
    level = 1
    section = "1 - Identity & Access Management"
    rationale = "MFA is the single most effective control against account compromise."
    remediation = (
        "Create a CA policy: All users → All cloud apps → Grant access, require MFA. "
        "Exclude break-glass accounts from the policy."
    )
    reference = "CIS M365 v3.1 §1.2.1 | CIS Entra v2.0 §1.2"

    def run(self, ctx: PolicyContext) -> CheckResult:
        # Security Defaults covers MFA for all users
        if _security_defaults_enabled(ctx):
            return self._result(
                CheckStatus.PASS,
                expected="MFA required for all users",
                actual="Covered by Security Defaults",
            )

        mfa_all_users_policies = [
            p for p in ctx.ca_policies
            if _ca_enabled(p) and _ca_includes_all_users(p) and _ca_requires_mfa(p)
        ]

        if mfa_all_users_policies:
            names = ", ".join(p.get("displayName", "unnamed") for p in mfa_all_users_policies)
            return self._result(
                CheckStatus.PASS,
                expected="CA policy requiring MFA for all users",
                actual=f"Policy found: {names}",
            )

        # Check for report-only policies (WARN)
        report_only = [
            p for p in ctx.ca_policies
            if p.get("state", "").lower() == "enabledforreportingbutnotenforced"
            and _ca_includes_all_users(p)
            and _ca_requires_mfa(p)
        ]
        if report_only:
            names = ", ".join(p.get("displayName", "unnamed") for p in report_only)
            return self._result(
                CheckStatus.WARN,
                expected="Enabled CA policy requiring MFA for all users",
                actual=f"Policy exists but is in report-only mode: {names}",
                notes="Enable the policy to enforce MFA.",
            )

        return self._result(
            CheckStatus.FAIL,
            expected="CA policy requiring MFA for all users",
            actual="No enabled CA policy found that requires MFA for all users",
        )


class CheckMFAAdmins(BaseCheck):
    """
    M365-1.2.2
    Ensure privileged admin accounts require MFA.
    """
    control_id = "M365-1.2.2"
    title = "MFA required for administrator roles"
    benchmark = "CIS M365 & Entra"
    level = 1
    section = "1 - Identity & Access Management"
    rationale = "Admin accounts are high-value targets. MFA is mandatory to prevent privilege escalation."
    remediation = (
        "Create a CA policy targeting all administrator directory roles "
        "→ All cloud apps → Grant access, require MFA."
    )
    reference = "CIS M365 v3.1 §1.2.2 | CIS Entra v2.0 §1.2"

    def run(self, ctx: PolicyContext) -> CheckResult:
        if _security_defaults_enabled(ctx):
            return self._result(
                CheckStatus.PASS,
                expected="MFA required for admins",
                actual="Covered by Security Defaults",
            )

        mfa_admin_policies = [
            p for p in ctx.ca_policies
            if _ca_enabled(p)
            and (_ca_includes_admin_roles(p) or _ca_includes_all_users(p))
            and _ca_requires_mfa(p)
        ]

        if mfa_admin_policies:
            names = ", ".join(p.get("displayName", "unnamed") for p in mfa_admin_policies)
            return self._result(
                CheckStatus.PASS,
                expected="CA policy requiring MFA for admin roles",
                actual=f"Policy found: {names}",
            )

        return self._result(
            CheckStatus.FAIL,
            expected="CA policy requiring MFA for admin roles",
            actual="No enabled CA policy found that requires MFA for admin roles",
        )


class CheckMFAAzureManagement(BaseCheck):
    """
    M365-1.2.3 / Entra-1.2.3
    Ensure MFA is required for Azure Management (portal, CLI, PowerShell).
    Level 2 — stricter environments.
    """
    control_id = "M365-1.2.3"
    title = "MFA required for Azure Management"
    benchmark = "CIS M365 & Entra"
    level = 2
    section = "1 - Identity & Access Management"
    rationale = "Azure management interfaces expose subscription-level controls. Compromise enables full tenant takeover."
    remediation = (
        "Create a CA policy: All users → Cloud app: 'Microsoft Azure Management' "
        "(App ID: 797f4846-ba00-4fd7-ba43-dac1f8f63013) → Require MFA."
    )
    reference = "CIS M365 v3.1 §1.2.3 | CIS Entra v2.0 §1.3"

    AZURE_MGMT_APP_ID = "797f4846-ba00-4fd7-ba43-dac1f8f63013"

    def run(self, ctx: PolicyContext) -> CheckResult:
        if _security_defaults_enabled(ctx):
            return self._result(
                CheckStatus.PASS,
                expected="MFA required for Azure Management",
                actual="Covered by Security Defaults",
            )

        azure_mfa_policies = []
        for p in ctx.ca_policies:
            if not _ca_enabled(p) or not _ca_requires_mfa(p):
                continue
            apps = (p.get("conditions") or {}).get("applications") or {}
            include_apps = apps.get("includeApplications", [])
            if "All" in include_apps or self.AZURE_MGMT_APP_ID in include_apps:
                if _ca_includes_all_users(p) or _ca_includes_admin_roles(p):
                    azure_mfa_policies.append(p)

        if azure_mfa_policies:
            names = ", ".join(p.get("displayName", "unnamed") for p in azure_mfa_policies)
            return self._result(
                CheckStatus.PASS,
                expected="CA policy requiring MFA for Azure Management",
                actual=f"Policy found: {names}",
            )

        return self._result(
            CheckStatus.FAIL,
            expected="CA policy requiring MFA for Azure Management app",
            actual="No CA policy found requiring MFA for Azure Management",
        )


# ---------------------------------------------------------------------------
# 1.3 — App Consent & Permissions
# ---------------------------------------------------------------------------

class CheckUserAppConsent(BaseCheck):
    """
    M365-1.3.1
    Ensure users cannot consent to apps accessing company data on their behalf.
    """
    control_id = "M365-1.3.1"
    title = "Users cannot consent to unverified apps"
    benchmark = "CIS M365 & Entra"
    level = 1
    section = "1 - Identity & Access Management"
    rationale = "OAuth phishing relies on users consenting to malicious apps. Restricting consent prevents this attack vector."
    remediation = (
        "Entra ID > Enterprise Applications > Consent and Permissions > "
        "User consent settings: set to 'Do not allow user consent' or "
        "'Allow user consent for apps from verified publishers only'."
    )
    reference = "CIS M365 v3.1 §1.3.1 | CIS Entra v2.0 §2.1"

    def run(self, ctx: PolicyContext) -> CheckResult:
        auth = ctx.authorization_policy
        if not auth:
            return self._result(CheckStatus.ERROR, "Restricted consent", "Unable to fetch authorization policy", "")

        assigned = auth.get("defaultUserRolePermissions", {}).get(
            "permissionGrantPoliciesAssigned", []
        )

        if not assigned:
            return self._result(
                CheckStatus.PASS,
                expected="User consent disabled or restricted to verified publishers",
                actual="No permission grant policies assigned (user consent disabled)",
            )

        policies_str = ", ".join(assigned)

        # managePermissionGrantsForSelf.microsoft-user-default-legacy-v2 = allow all (BAD)
        if any("legacy" in p.lower() or "microsoft-user-default-legacy" in p.lower() for p in assigned):
            return self._result(
                CheckStatus.FAIL,
                expected="User consent disabled or restricted to verified publishers",
                actual=f"Users can consent to any app: {policies_str}",
            )

        # microsoft-user-default-low = allow low-risk permissions from verified publishers (WARN/PASS)
        if any("low" in p.lower() or "verified" in p.lower() for p in assigned):
            return self._result(
                CheckStatus.WARN,
                expected="User consent disabled (preferred) or restricted to verified publishers",
                actual=f"Users can consent to low-risk verified-publisher apps: {policies_str}",
                notes="Acceptable if admin consent workflow is enabled for all other requests.",
            )

        return self._result(
            CheckStatus.WARN,
            expected="User consent disabled or clearly restricted",
            actual=f"Consent policy configured: {policies_str}",
            notes="Review the configured grant policies to verify they are appropriately restrictive.",
        )


class CheckAdminConsentWorkflow(BaseCheck):
    """
    M365-1.3.2
    Ensure the admin consent request workflow is enabled.
    """
    control_id = "M365-1.3.2"
    title = "Admin consent workflow enabled"
    benchmark = "CIS M365 & Entra"
    level = 1
    section = "1 - Identity & Access Management"
    rationale = "Admin consent workflow provides an approval process for app permission requests, preventing shadow IT and OAuth phishing persistence."
    remediation = (
        "Entra ID > Enterprise Applications > Consent and Permissions > "
        "Admin consent requests: Enable 'Users can request admin consent to apps'."
    )
    reference = "CIS M365 v3.1 §1.3.2"

    def run(self, ctx: PolicyContext) -> CheckResult:
        policy = ctx.admin_consent_policy
        if not policy:
            return self._result(CheckStatus.ERROR, "Enabled", "Unable to fetch admin consent policy", "")

        is_enabled = policy.get("isEnabled", False)
        if is_enabled:
            return self._result(
                CheckStatus.PASS,
                expected="Admin consent workflow enabled",
                actual="Admin consent workflow: Enabled",
            )
        return self._result(
            CheckStatus.FAIL,
            expected="Admin consent workflow enabled",
            actual="Admin consent workflow: Disabled",
        )


# ---------------------------------------------------------------------------
# 1.4 — Legacy Authentication
# ---------------------------------------------------------------------------

class CheckBlockLegacyAuth(BaseCheck):
    """
    M365-1.4.1 / Entra-1.4.1
    Ensure legacy authentication protocols are blocked via Conditional Access.
    """
    control_id = "M365-1.4.1"
    title = "Legacy authentication protocols blocked"
    benchmark = "CIS M365 & Entra"
    level = 1
    section = "1 - Identity & Access Management"
    rationale = (
        "Legacy auth clients (IMAP, POP3, SMTP AUTH, Basic Auth, older Office clients) "
        "do not support MFA and are a primary vector for password spray attacks."
    )
    remediation = (
        "Create a CA policy: All users → All cloud apps → "
        "Conditions: Client apps = Exchange ActiveSync + Other → Block access."
    )
    reference = "CIS M365 v3.1 §1.4.1 | CIS Entra v2.0 §1.4"

    def run(self, ctx: PolicyContext) -> CheckResult:
        if _security_defaults_enabled(ctx):
            return self._result(
                CheckStatus.PASS,
                expected="Legacy authentication blocked",
                actual="Covered by Security Defaults",
            )

        blocking_policies = []
        for p in ctx.ca_policies:
            if not _ca_enabled(p):
                continue
            conditions = p.get("conditions") or {}
            client_apps = conditions.get("clientAppTypes") or []
            apps_lower = [a.lower() for a in client_apps]
            has_legacy = "exchangeactivesync" in apps_lower or "other" in apps_lower

            grant = p.get("grantControls") or {}
            built_in = [c.lower() for c in (grant.get("builtInControls") or [])]
            is_block = "block" in built_in or (not built_in and not grant.get("customAuthenticationFactors"))

            if has_legacy and is_block:
                blocking_policies.append(p)

        if blocking_policies:
            names = ", ".join(p.get("displayName", "unnamed") for p in blocking_policies)
            return self._result(
                CheckStatus.PASS,
                expected="CA policy blocking legacy auth protocols",
                actual=f"Policy found: {names}",
            )

        return self._result(
            CheckStatus.FAIL,
            expected="CA policy blocking legacy authentication",
            actual="No CA policy found that blocks legacy authentication protocols",
        )


# ---------------------------------------------------------------------------
# 1.5 — Guest Access
# ---------------------------------------------------------------------------

class CheckGuestInviteRestrictions(BaseCheck):
    """
    M365-1.5.1 / Entra-1.5.1
    Ensure only admins (or member users) can invite external guests.
    """
    control_id = "M365-1.5.1"
    title = "Guest invite restrictions"
    benchmark = "CIS M365 & Entra"
    level = 1
    section = "1 - Identity & Access Management"
    rationale = "Unrestricted guest invites allow any user to add external identities, expanding the attack surface."
    remediation = (
        "Entra ID > External Identities > External collaboration settings: "
        "Set 'Guest invite settings' to 'Only users assigned to specific admin roles can invite' "
        "or 'Admins and users in the guest inviter role can invite'."
    )
    reference = "CIS M365 v3.1 §1.5.1 | CIS Entra v2.0 §3.1"

    # Mapping of allowInvitesFrom values to risk levels
    INVITE_RISK = {
        "none": "PASS",
        "adminsAndGuestInviters": "PASS",
        "adminsGuestInvitersAndAllMembers": "WARN",
        "everyone": "FAIL",
    }

    def run(self, ctx: PolicyContext) -> CheckResult:
        auth = ctx.authorization_policy
        if not auth:
            return self._result(CheckStatus.ERROR, "Restricted", "Unable to fetch authorization policy", "")

        allow_invites = auth.get("allowInvitesFrom", "everyone")
        risk = self.INVITE_RISK.get(allow_invites, "WARN")
        status = CheckStatus[risk]

        return self._result(
            status,
            expected="adminsAndGuestInviters or none",
            actual=f"allowInvitesFrom: {allow_invites}",
        )


class CheckGuestUserPermissions(BaseCheck):
    """
    M365-1.5.2 / Entra-1.5.2
    Ensure guest user access is restricted (cannot see full directory).
    """
    control_id = "M365-1.5.2"
    title = "Guest user directory permissions restricted"
    benchmark = "CIS M365 & Entra"
    level = 1
    section = "1 - Identity & Access Management"
    rationale = "Guest accounts with broad directory permissions can enumerate all users and groups, aiding internal recon."
    remediation = (
        "Entra ID > External Identities > External collaboration settings: "
        "Set 'Guest user access restrictions' to "
        "'Guest users have limited access to properties and memberships of directory objects'."
    )
    reference = "CIS M365 v3.1 §1.5.2 | CIS Entra v2.0 §3.2"

    # guestUserRoleId mappings
    # 10dae51f-b6af-4016-8d66-8c2a99b929b3 = same as member (most permissive — BAD)
    # bf59c301-1cff-4c7a-a7b7-a5e8c17e1610 = limited access (recommended)
    # 2af84b1e-32c8-42b7-82bc-daa82404023b = restricted (most restrictive)
    ROLE_RISK = {
        "10dae51f-b6af-4016-8d66-8c2a99b929b3": ("FAIL", "Guest access same as member (most permissive)"),
        "bf59c301-1cff-4c7a-a7b7-a5e8c17e1610": ("PASS", "Guest users have limited access (recommended)"),
        "2af84b1e-32c8-42b7-82bc-daa82404023b": ("PASS", "Guest users have restricted access (most restrictive)"),
    }

    def run(self, ctx: PolicyContext) -> CheckResult:
        auth = ctx.authorization_policy
        if not auth:
            return self._result(CheckStatus.ERROR, "Limited or restricted", "Unable to fetch authorization policy", "")

        role_id = auth.get("guestUserRoleId", "")
        risk, description = self.ROLE_RISK.get(role_id, ("WARN", f"Unknown role ID: {role_id}"))
        status = CheckStatus[risk]

        return self._result(
            status,
            expected="Limited or restricted guest access (not 'same as member')",
            actual=description,
        )


# ---------------------------------------------------------------------------
# 1.6 — SSPR (Self-Service Password Reset)
# ---------------------------------------------------------------------------

class CheckSSPREnabled(BaseCheck):
    """
    M365-1.6.1
    Ensure Self-Service Password Reset is enabled.
    """
    control_id = "M365-1.6.1"
    title = "Self-Service Password Reset (SSPR) enabled"
    benchmark = "CIS M365"
    level = 1
    section = "1 - Identity & Access Management"
    rationale = "SSPR reduces helpdesk load and ensures users can recover accounts securely without calling IT."
    remediation = (
        "Entra ID > Password reset > Properties: "
        "Set 'Self service password reset enabled' to 'All' or targeted group."
    )
    reference = "CIS M365 v3.1 §1.6.1"

    def run(self, ctx: PolicyContext) -> CheckResult:
        auth = ctx.authorization_policy
        if not auth:
            return self._result(CheckStatus.ERROR, "Enabled", "Unable to fetch authorization policy", "")

        # allowedToUseSSPR: true = enabled for all, false = disabled
        sspr = auth.get("allowedToUseSSPR", None)
        if sspr is True:
            return self._result(
                CheckStatus.PASS,
                expected="SSPR enabled",
                actual="SSPR: Enabled (all users)",
            )
        elif sspr is False:
            return self._result(
                CheckStatus.WARN,
                expected="SSPR enabled for all users",
                actual="SSPR: Disabled or restricted",
                notes="Verify in Entra ID > Password reset. Policy API may not reflect group-scoped SSPR.",
            )
        return self._result(
            CheckStatus.WARN,
            expected="SSPR enabled",
            actual="SSPR status could not be determined from policy API",
            notes="Verify manually in Entra ID > Password reset > Properties.",
        )


# ---------------------------------------------------------------------------
# Export all checks in this module
# ---------------------------------------------------------------------------

IDENTITY_CHECKS: list[type[BaseCheck]] = [
    CheckSecurityDefaults,
    CheckModernAuthExchange,
    CheckMFAAllUsers,
    CheckMFAAdmins,
    CheckMFAAzureManagement,
    CheckUserAppConsent,
    CheckAdminConsentWorkflow,
    CheckBlockLegacyAuth,
    CheckGuestInviteRestrictions,
    CheckGuestUserPermissions,
    CheckSSPREnabled,
]
