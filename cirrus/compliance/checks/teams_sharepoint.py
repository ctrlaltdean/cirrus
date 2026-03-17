"""
CIS Compliance Checks — Section 4 & 5: Microsoft Teams & SharePoint Online

Most settings require the Teams or SharePoint admin PowerShell modules
or the respective admin centers. All represented as MANUAL checks.
"""

from __future__ import annotations

from cirrus.compliance.base import BaseCheck, ManualCheck

# ---------------------------------------------------------------------------
# Section 4 — Microsoft Teams
# ---------------------------------------------------------------------------

class CheckTeamsExternalAccess(ManualCheck):
    control_id = "M365-4.1.1"
    title = "Teams external access restricted to specific domains"
    benchmark = "CIS M365"
    level = 1
    section = "4 - Microsoft Teams"
    expected = "External access restricted to specific allowed domains, not 'all external domains'"
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
        "  Expected: AllowFederatedUsers = True with specific AllowedDomains\n"
        "            OR AllowFederatedUsers = False (blocks all external federation)\n\n"
        "Flag if: AllowFederatedUsers = True AND AllowedDomains = AllDomains"
    )
    reference = "CIS M365 v3.1 §4.1.1"


class CheckTeamsGuestAccess(ManualCheck):
    control_id = "M365-4.1.2"
    title = "Teams guest access restricted"
    benchmark = "CIS M365"
    level = 1
    section = "4 - Microsoft Teams"
    expected = "Guest users have limited capabilities; cannot initiate meetings or access teams they are not invited to"
    rationale = "Overly permissive guest access in Teams allows external users to view sensitive communications and files."
    remediation = "Teams Admin Center > Users > Guest access: Review and restrict guest capabilities."
    manual_steps = (
        "Teams Admin Center:\n"
        "  https://admin.teams.microsoft.com > Users > Guest access\n\n"
        "Verify:\n"
        "  - Allow guest access: Enabled (required for external collaboration) but with restrictions\n"
        "  - Guest calling: Private calls allowed = disabled (if not needed)\n"
        "  - Guest meeting: IP video / Screen sharing = restricted\n"
        "  - Guest messaging: Delete sent messages = disabled\n\n"
        "PowerShell:\n"
        "  Get-CsTeamsGuestCallingConfiguration\n"
        "  Get-CsTeamsGuestMeetingConfiguration\n"
        "  Get-CsTeamsGuestMessagingConfiguration"
    )
    reference = "CIS M365 v3.1 §4.1.2"


class CheckTeamsMeetingAnonymousJoin(ManualCheck):
    control_id = "M365-4.1.3"
    title = "Anonymous meeting join restricted"
    benchmark = "CIS M365"
    level = 2
    section = "4 - Microsoft Teams"
    expected = "Anonymous users cannot join meetings without being admitted by an authenticated user"
    rationale = "Anonymous join allows unauthenticated external parties to join meetings, risking eavesdropping on sensitive calls."
    remediation = "Teams Admin Center > Meetings > Meeting policies: Set 'Let anonymous people join a meeting' to Off or require lobby."
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


# ---------------------------------------------------------------------------
# Section 5 — SharePoint Online & OneDrive
# ---------------------------------------------------------------------------

class CheckSharePointExternalSharing(ManualCheck):
    control_id = "M365-5.1.1"
    title = "SharePoint external sharing restricted"
    benchmark = "CIS M365"
    level = 1
    section = "5 - SharePoint & OneDrive"
    expected = "SharePoint sharing set to 'Existing guests' or 'Only people in your organization'"
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
        "PowerShell (SharePoint Online module):\n"
        "  Connect-SPOService -Url https://<tenant>-admin.sharepoint.com\n"
        "  Get-SPOTenant | Select-Object SharingCapability, OneDriveSharingCapability\n"
        "  SharingCapability values:\n"
        "    0 = Disabled (only org users)\n"
        "    1 = ExistingExternalUserSharingOnly\n"
        "    2 = ExternalUserSharingOnly (no anonymous)\n"
        "    3 = ExternalUserAndGuestSharing (Anyone links — FLAG THIS)\n"
        "  Expected: 0 or 1"
    )
    reference = "CIS M365 v3.1 §5.1.1"


class CheckSharePointDefaultSharingLink(ManualCheck):
    control_id = "M365-5.1.2"
    title = "Default sharing link is not 'Anyone'"
    benchmark = "CIS M365"
    level = 1
    section = "5 - SharePoint & OneDrive"
    expected = "Default sharing link type is 'People in your organization' or 'Specific people'"
    rationale = "If the default link type is 'Anyone', users inadvertently create anonymous links when sharing, enabling unrestricted access."
    remediation = (
        "SharePoint Admin Center > Policies > Sharing > Default link type:\n"
        "Set to 'People in your organization' or 'Specific people'."
    )
    manual_steps = (
        "SharePoint Admin Center:\n"
        "  https://admin.microsoft.com > SharePoint > Policies > Sharing\n"
        "  > 'Default link type' section\n\n"
        "PowerShell:\n"
        "  Get-SPOTenant | Select-Object DefaultSharingLinkType\n"
        "  DefaultSharingLinkType values:\n"
        "    1 = Direct (Specific people) — OK\n"
        "    2 = Internal (People in your org) — OK\n"
        "    3 = AnonymousAccess (Anyone) — FLAG THIS"
    )
    reference = "CIS M365 v3.1 §5.1.2"


class CheckSharePointLegacyAuth(ManualCheck):
    control_id = "M365-5.1.3"
    title = "SharePoint legacy authentication disabled"
    benchmark = "CIS M365"
    level = 2
    section = "5 - SharePoint & OneDrive"
    expected = "SharePoint does not allow legacy (non-modern) authentication"
    rationale = "Legacy authentication to SharePoint bypasses Conditional Access policies including MFA requirements."
    remediation = "SharePoint Admin Center > Access control: Disable legacy authentication."
    manual_steps = (
        "SharePoint Admin Center:\n"
        "  https://admin.microsoft.com > SharePoint > Policies > Access control\n"
        "  > Apps that don't use modern authentication: Block access\n\n"
        "PowerShell:\n"
        "  Get-SPOTenant | Select-Object LegacyAuthProtocolsEnabled\n"
        "  Expected: False"
    )
    reference = "CIS M365 v3.1 §5.1.3"


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
