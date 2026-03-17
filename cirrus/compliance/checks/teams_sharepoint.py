"""
CIS Compliance Checks — Section 4 & 5: Microsoft Teams & SharePoint Online

Hybrid checks: automated when Teams/SharePoint PowerShell data is available
in PolicyContext; falls back to MANUAL with step-by-step instructions.

Teams checks require: MicrosoftTeams PS module
SharePoint checks require: Microsoft.Online.SharePoint.PowerShell module
"""

from __future__ import annotations

from cirrus.compliance.base import BaseCheck, CheckResult, CheckStatus
from cirrus.compliance.context import PolicyContext


def _teams_available(ctx: PolicyContext) -> bool:
    return bool(ctx.teams_ps and ctx.teams_ps.available)


def _spo_available(ctx: PolicyContext) -> bool:
    return bool(ctx.sharepoint_ps and ctx.sharepoint_ps.available)


# ---------------------------------------------------------------------------
# Section 4 — Microsoft Teams
# ---------------------------------------------------------------------------

class CheckTeamsExternalAccess(BaseCheck):
    control_id = "M365-4.1.1"
    title = "Teams external access restricted to specific domains"
    benchmark = "CIS M365"
    level = 1
    section = "4 - Microsoft Teams"
    expected = "External access disabled or restricted to specific allowed domains (not all external domains)"
    rationale = "Unrestricted Teams external access allows federation with any tenant, including attacker-controlled ones used for phishing or data theft."
    remediation = (
        "Teams Admin Center > Users > External access:\n"
        "Set to 'Allow only specific external domains' and add trusted partners."
    )
    manual_steps = (
        "Teams Admin Center:\n"
        "  https://admin.teams.microsoft.com > Users > External access\n\n"
        "Microsoft Teams PowerShell:\n"
        "  1. Connect-MicrosoftTeams\n"
        "  2. Get-CsTenantFederationConfiguration | Select AllowFederatedUsers, AllowedDomains\n"
        "  Expected: AllowFederatedUsers = False\n"
        "            OR AllowFederatedUsers = True with specific AllowedDomains (not AllowAllKnownDomains)\n\n"
        "Flag if: AllowFederatedUsers = True AND AllowedDomains = AllAllowed (open federation)"
    )
    reference = "CIS M365 v3.1 §4.1.1"

    def run(self, ctx: PolicyContext) -> CheckResult:
        if not _teams_available(ctx):
            ps_error = ctx.teams_ps.error if ctx.teams_ps else "Teams PS not run"
            return self._result(
                CheckStatus.MANUAL, self.expected,
                f"Teams PS unavailable: {ps_error}",
                notes=self.manual_steps,
            )

        fed = ctx.teams_ps.federation_config
        if "Error" in fed:
            return self._result(
                CheckStatus.MANUAL, self.expected,
                f"Get-CsTenantFederationConfiguration error: {fed['Error']}",
                notes=self.manual_steps,
            )

        allow_federated = fed.get("AllowFederatedUsers", False)
        allowed_domains_is_all = fed.get("AllowedDomainsIsAll", False)

        if not allow_federated:
            return self._result(
                CheckStatus.PASS, self.expected,
                "AllowFederatedUsers = False — external federation is blocked",
            )

        if allow_federated and allowed_domains_is_all:
            return self._result(
                CheckStatus.FAIL, self.expected,
                "AllowFederatedUsers = True AND AllowedDomains = AllAllowed — open federation with any tenant",
            )

        domain_count = fed.get("AllowedDomainCount", 0)
        return self._result(
            CheckStatus.PASS, self.expected,
            f"AllowFederatedUsers = True but restricted to {domain_count} specific domain(s)",
        )


class CheckTeamsGuestAccess(BaseCheck):
    control_id = "M365-4.1.2"
    title = "Teams guest access restricted"
    benchmark = "CIS M365"
    level = 1
    section = "4 - Microsoft Teams"
    expected = "Guest users have limited capabilities; cannot initiate meetings or conduct screen sharing unilaterally"
    rationale = "Overly permissive guest access in Teams allows external users to view sensitive communications and files."
    remediation = "Teams Admin Center > Users > Guest access: Review and restrict guest calling, meeting, and messaging capabilities."
    manual_steps = (
        "Teams Admin Center:\n"
        "  https://admin.teams.microsoft.com > Users > Guest access\n\n"
        "Verify restricted guest capabilities:\n"
        "  - Private calls: disabled (unless required)\n"
        "  - IP video / Screen sharing: restricted\n"
        "  - Delete sent messages: disabled\n\n"
        "PowerShell:\n"
        "  Get-CsTeamsGuestCallingConfiguration\n"
        "  Get-CsTeamsGuestMeetingConfiguration\n"
        "  Get-CsTeamsGuestMessagingConfiguration"
    )
    reference = "CIS M365 v3.1 §4.1.2"

    def run(self, ctx: PolicyContext) -> CheckResult:
        if not _teams_available(ctx):
            ps_error = ctx.teams_ps.error if ctx.teams_ps else "Teams PS not run"
            return self._result(
                CheckStatus.MANUAL, self.expected,
                f"Teams PS unavailable: {ps_error}",
                notes=self.manual_steps,
            )

        issues = []
        calling = ctx.teams_ps.guest_calling_config
        if calling.get("AllowPrivateCalling") is True:
            issues.append("Guest private calling enabled (AllowPrivateCalling=True)")

        meeting = ctx.teams_ps.guest_meeting_config
        if meeting.get("ScreenSharingMode", "").lower() not in ("disabled", "singlepresenter"):
            mode = meeting.get("ScreenSharingMode", "unknown")
            if mode and "Error" not in str(mode):
                issues.append(f"Guest screen sharing not restricted (ScreenSharingMode={mode})")

        messaging = ctx.teams_ps.guest_messaging_config
        if messaging.get("AllowDeleteSentMessages") is True:
            issues.append("Guests can delete sent messages")

        if issues:
            return self._result(
                CheckStatus.WARN, self.expected,
                f"Guest access not fully restricted: {'; '.join(issues)}",
                notes="Review guest settings in Teams Admin Center > Users > Guest access.",
            )

        return self._result(
            CheckStatus.PASS, self.expected,
            "Guest calling, meeting, and messaging settings are appropriately restricted",
        )


class CheckTeamsMeetingAnonymousJoin(BaseCheck):
    control_id = "M365-4.1.3"
    title = "Anonymous meeting join restricted"
    benchmark = "CIS M365"
    level = 2
    section = "4 - Microsoft Teams"
    expected = "AllowAnonymousUsersToJoinMeeting = False in Global meeting policy"
    rationale = "Anonymous join allows unauthenticated external parties to join meetings, risking eavesdropping on sensitive calls."
    remediation = "Teams Admin Center > Meetings > Meeting policies > (Global policy) > Set 'Let anonymous people join a meeting' to Off."
    manual_steps = (
        "Teams Admin Center:\n"
        "  https://admin.teams.microsoft.com > Meetings > Meeting policies\n"
        "  > (Global policy) > Participants & guests\n"
        "  > Anonymous users can join a meeting: Off\n\n"
        "PowerShell:\n"
        "  Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowAnonymousUsersToJoinMeeting\n"
        "  Expected: AllowAnonymousUsersToJoinMeeting = False"
    )
    reference = "CIS M365 v3.1 §4.1.3"

    def run(self, ctx: PolicyContext) -> CheckResult:
        if not _teams_available(ctx):
            ps_error = ctx.teams_ps.error if ctx.teams_ps else "Teams PS not run"
            return self._result(
                CheckStatus.MANUAL, self.expected,
                f"Teams PS unavailable: {ps_error}",
                notes=self.manual_steps,
            )

        mp = ctx.teams_ps.meeting_policy_global
        if "Error" in mp:
            return self._result(
                CheckStatus.MANUAL, self.expected,
                f"Get-CsTeamsMeetingPolicy error: {mp['Error']}",
                notes=self.manual_steps,
            )

        allow_anon = mp.get("AllowAnonymousUsersToJoinMeeting")
        if allow_anon is False:
            return self._result(
                CheckStatus.PASS, self.expected,
                "AllowAnonymousUsersToJoinMeeting = False in Global meeting policy",
            )
        if allow_anon is True:
            return self._result(
                CheckStatus.FAIL, self.expected,
                "AllowAnonymousUsersToJoinMeeting = True — anonymous users can join meetings",
            )

        return self._result(
            CheckStatus.MANUAL, self.expected,
            "AllowAnonymousUsersToJoinMeeting state unknown — verify manually",
            notes=self.manual_steps,
        )


# ---------------------------------------------------------------------------
# Section 5 — SharePoint Online & OneDrive
# ---------------------------------------------------------------------------

# SharingCapability values (Get-SPOTenant)
_SPO_SHARING = {
    0: "Disabled (org users only)",
    1: "ExistingExternalUserSharingOnly",
    2: "ExternalUserSharingOnly (no anonymous)",
    3: "ExternalUserAndGuestSharing (Anyone links — OPEN)",
}


class CheckSharePointExternalSharing(BaseCheck):
    control_id = "M365-5.1.1"
    title = "SharePoint external sharing restricted"
    benchmark = "CIS M365"
    level = 1
    section = "5 - SharePoint & OneDrive"
    expected = "SharingCapability ≤ 1 (ExistingExternalUsers or Disabled)"
    rationale = "Unrestricted external sharing enables data exfiltration. 'Anyone' links require no authentication and are persistent."
    remediation = (
        "SharePoint Admin Center > Policies > Sharing:\n"
        "Set SharePoint and OneDrive sharing to 'Existing guests' or 'Only people in your organization'."
    )
    manual_steps = (
        "SharePoint Admin Center:\n"
        "  https://admin.microsoft.com > SharePoint > Policies > Sharing\n\n"
        "Verify:\n"
        "  SharePoint: 'Existing guests' or 'Only people in your organization'\n"
        "  OneDrive:   Same or more restrictive than SharePoint\n\n"
        "PowerShell:\n"
        "  Connect-SPOService -Url https://<tenant>-admin.sharepoint.com\n"
        "  Get-SPOTenant | Select-Object SharingCapability, OneDriveSharingCapability\n"
        "  Expected SharingCapability: 0 or 1  (3 = Anyone links — FLAG)"
    )
    reference = "CIS M365 v3.1 §5.1.1"

    def run(self, ctx: PolicyContext) -> CheckResult:
        if not _spo_available(ctx):
            ps_error = ctx.sharepoint_ps.error if ctx.sharepoint_ps else "SPO PS not run"
            return self._result(
                CheckStatus.MANUAL, self.expected,
                f"SharePoint PS unavailable: {ps_error}",
                notes=self.manual_steps,
            )

        tenant = ctx.sharepoint_ps.spo_tenant
        if "Error" in tenant:
            return self._result(
                CheckStatus.MANUAL, self.expected,
                f"Get-SPOTenant error: {tenant['Error']}",
                notes=self.manual_steps,
            )

        sharing = tenant.get("SharingCapability")
        od_sharing = tenant.get("OneDriveSharingCapability")

        if sharing is None:
            return self._result(
                CheckStatus.MANUAL, self.expected,
                "SharingCapability not returned — verify manually",
                notes=self.manual_steps,
            )

        sharing_label = _SPO_SHARING.get(sharing, f"Unknown ({sharing})")
        od_label = _SPO_SHARING.get(od_sharing, f"Unknown ({od_sharing})") if od_sharing is not None else "not returned"

        if sharing == 3 or od_sharing == 3:
            return self._result(
                CheckStatus.FAIL, self.expected,
                f"SharePoint={sharing_label}; OneDrive={od_label} — 'Anyone' links enabled",
            )

        if sharing <= 1:
            return self._result(
                CheckStatus.PASS, self.expected,
                f"SharePoint={sharing_label}; OneDrive={od_label}",
            )

        return self._result(
            CheckStatus.WARN, self.expected,
            f"SharePoint={sharing_label}; OneDrive={od_label} — review if external sharing is appropriate",
        )


class CheckSharePointDefaultSharingLink(BaseCheck):
    control_id = "M365-5.1.2"
    title = "Default sharing link is not 'Anyone'"
    benchmark = "CIS M365"
    level = 1
    section = "5 - SharePoint & OneDrive"
    expected = "DefaultSharingLinkType ≠ 3 (not 'AnonymousAccess')"
    rationale = "If the default link type is 'Anyone', users inadvertently create anonymous links when sharing, enabling unrestricted access."
    remediation = (
        "SharePoint Admin Center > Policies > Sharing > Default link type:\n"
        "Set to 'People in your organization' or 'Specific people'."
    )
    manual_steps = (
        "SharePoint Admin Center > Policies > Sharing > 'Default link type'\n\n"
        "PowerShell:\n"
        "  Get-SPOTenant | Select-Object DefaultSharingLinkType\n"
        "  Values: 1=Direct(OK), 2=Internal(OK), 3=AnonymousAccess(FLAG)"
    )
    reference = "CIS M365 v3.1 §5.1.2"

    _LINK_TYPES = {1: "Direct (Specific people)", 2: "Internal (People in org)", 3: "AnonymousAccess (Anyone — FAIL)"}

    def run(self, ctx: PolicyContext) -> CheckResult:
        if not _spo_available(ctx):
            ps_error = ctx.sharepoint_ps.error if ctx.sharepoint_ps else "SPO PS not run"
            return self._result(
                CheckStatus.MANUAL, self.expected,
                f"SharePoint PS unavailable: {ps_error}",
                notes=self.manual_steps,
            )

        tenant = ctx.sharepoint_ps.spo_tenant
        link_type = tenant.get("DefaultSharingLinkType")

        if link_type is None:
            return self._result(
                CheckStatus.MANUAL, self.expected,
                "DefaultSharingLinkType not returned — verify manually",
                notes=self.manual_steps,
            )

        label = self._LINK_TYPES.get(link_type, f"Unknown ({link_type})")

        if link_type == 3:
            return self._result(CheckStatus.FAIL, self.expected, f"DefaultSharingLinkType={label}")
        return self._result(CheckStatus.PASS, self.expected, f"DefaultSharingLinkType={label}")


class CheckSharePointLegacyAuth(BaseCheck):
    control_id = "M365-5.1.3"
    title = "SharePoint legacy authentication disabled"
    benchmark = "CIS M365"
    level = 2
    section = "5 - SharePoint & OneDrive"
    expected = "LegacyAuthProtocolsEnabled = False"
    rationale = "Legacy authentication to SharePoint bypasses Conditional Access policies including MFA requirements."
    remediation = "SharePoint Admin Center > Policies > Access control > Apps that don't use modern authentication: Block access."
    manual_steps = (
        "SharePoint Admin Center > Policies > Access control\n"
        "  > Apps that don't use modern authentication: Block access\n\n"
        "PowerShell:\n"
        "  Get-SPOTenant | Select-Object LegacyAuthProtocolsEnabled\n"
        "  Expected: False"
    )
    reference = "CIS M365 v3.1 §5.1.3"

    def run(self, ctx: PolicyContext) -> CheckResult:
        if not _spo_available(ctx):
            ps_error = ctx.sharepoint_ps.error if ctx.sharepoint_ps else "SPO PS not run"
            return self._result(
                CheckStatus.MANUAL, self.expected,
                f"SharePoint PS unavailable: {ps_error}",
                notes=self.manual_steps,
            )

        tenant = ctx.sharepoint_ps.spo_tenant
        legacy = tenant.get("LegacyAuthProtocolsEnabled")

        if legacy is False:
            return self._result(CheckStatus.PASS, self.expected, "LegacyAuthProtocolsEnabled = False")
        if legacy is True:
            return self._result(CheckStatus.FAIL, self.expected, "LegacyAuthProtocolsEnabled = True — legacy auth is permitted")

        return self._result(
            CheckStatus.MANUAL, self.expected,
            "LegacyAuthProtocolsEnabled state unknown — verify manually",
            notes=self.manual_steps,
        )


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

TEAMS_CHECKS: list[type[BaseCheck]] = [
    CheckTeamsExternalAccess,
    CheckTeamsGuestAccess,
    CheckTeamsMeetingAnonymousJoin,
]

SHAREPOINT_CHECKS: list[type[BaseCheck]] = [
    CheckSharePointExternalSharing,
    CheckSharePointDefaultSharingLink,
    CheckSharePointLegacyAuth,
]
