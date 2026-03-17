"""
CIS Compliance Checks — Section 6: Logging & Monitoring

Mix of automated (Graph API) and manual (Exchange PowerShell) checks.
"""

from __future__ import annotations

from cirrus.compliance.base import BaseCheck, CheckResult, CheckStatus, ManualCheck
from cirrus.compliance.context import PolicyContext


class CheckUnifiedAuditLog(ManualCheck):
    control_id = "M365-6.1.1"
    title = "Unified Audit Log search is enabled"
    benchmark = "CIS M365"
    level = 1
    section = "6 - Logging & Monitoring"
    expected = "Unified Audit Log enabled for the organization"
    rationale = "The UAL is the primary forensic data source for M365 investigations. If disabled, activity cannot be reconstructed."
    remediation = (
        "Exchange Online PowerShell:\n"
        "  Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true\n\n"
        "Or: Microsoft Purview compliance portal > Audit > Start recording user and admin activity"
    )
    manual_steps = (
        "Exchange Online PowerShell:\n"
        "  1. Connect-ExchangeOnline\n"
        "  2. Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled\n"
        "  Expected: True\n\n"
        "Microsoft Purview compliance portal:\n"
        "  https://compliance.microsoft.com > Audit\n"
        "  If audit search shows 'Start recording...', it is disabled."
    )
    reference = "CIS M365 v3.1 §6.1.1"


class CheckMailboxAuditEnabled(ManualCheck):
    control_id = "M365-6.1.2"
    title = "Mailbox auditing enabled for all users"
    benchmark = "CIS M365"
    level = 1
    section = "6 - Logging & Monitoring"
    expected = "AuditEnabled = True for all user mailboxes; MailboxAuditBypassAccess not set"
    rationale = "Mailbox audit logs record who accessed mailboxes and what actions were taken — critical for BEC investigation."
    remediation = (
        "Exchange Online PowerShell:\n"
        "  Set-OrganizationConfig -AuditDisabled $false\n"
        "  Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true"
    )
    manual_steps = (
        "Exchange Online PowerShell:\n"
        "  1. Connect-ExchangeOnline\n"
        "  2. Get-OrganizationConfig | Select-Object AuditDisabled\n"
        "     Expected: False (org-level auditing on)\n\n"
        "  3. Get-Mailbox -ResultSize Unlimited | Select-Object DisplayName, AuditEnabled\n"
        "     Filter for AuditEnabled = False — these are gaps\n\n"
        "  4. Check bypass list (these mailboxes are NOT audited):\n"
        "     Get-MailboxAuditBypassAssociation -ResultSize Unlimited\n"
        "     Expected: Empty or only system accounts"
    )
    reference = "CIS M365 v3.1 §6.1.2"


class CheckAuditLogRetention(ManualCheck):
    control_id = "M365-6.1.3"
    title = "Audit log retention is at least 90 days (1 year recommended)"
    benchmark = "CIS M365"
    level = 2
    section = "6 - Logging & Monitoring"
    expected = "Audit logs retained for at least 1 year (requires E3/E5 or add-on)"
    rationale = "BEC investigations often require reviewing activity months before the incident is detected. Short retention windows close that forensic window."
    remediation = (
        "Microsoft Purview compliance portal > Audit > Audit retention policies.\n"
        "Create a policy: All activities → Retain for 1 year (E3) or 10 years (E5).\n"
        "Default is 90 days (E1) or 1 year (E3/E5)."
    )
    manual_steps = (
        "Microsoft Purview compliance portal:\n"
        "  https://compliance.microsoft.com > Audit > Audit retention policies\n"
        "  Verify policies cover all workloads for at least 1 year\n\n"
        "PowerShell (Security & Compliance):\n"
        "  Connect-IPPSSession\n"
        "  Get-UnifiedAuditLogRetentionPolicy | Select-Object Name, RetentionDuration, RecordTypes\n"
        "  Expected: RetentionDuration >= OneYear for all critical workloads\n\n"
        "License note:\n"
        "  - E1: 90-day retention (default)\n"
        "  - E3: 1-year retention (default)\n"
        "  - E5 / Compliance add-on: Up to 10-year retention"
    )
    reference = "CIS M365 v3.1 §6.1.3"


class CheckAlertPolicies(BaseCheck):
    """
    M365-6.2.1
    Verify Microsoft Secure Score includes alert policy controls.
    Partially automated — checks Secure Score profiles for alert-related controls.
    """
    control_id = "M365-6.2.1"
    title = "Security alert policies configured"
    benchmark = "CIS M365"
    level = 1
    section = "6 - Logging & Monitoring"
    rationale = "Alert policies notify administrators of suspicious activity. Without alerts, incidents go undetected until discovered manually."
    remediation = (
        "Microsoft Defender portal > Policies & Rules > Alert policy:\n"
        "Enable and configure alert policies for: unusual admin activity, "
        "mass file downloads, mail forwarding rules, suspicious sign-ins."
    )
    reference = "CIS M365 v3.1 §6.2.1"

    ALERT_CONTROL_KEYWORDS = ["alert", "notification", "anomalous"]

    def run(self, ctx: PolicyContext) -> CheckResult:
        # Find alert-related controls in Secure Score profiles
        alert_profiles = [
            p for p in ctx.secure_score_profiles
            if any(kw in (p.get("controlName") or "").lower() for kw in self.ALERT_CONTROL_KEYWORDS)
            or any(kw in (p.get("title") or "").lower() for kw in self.ALERT_CONTROL_KEYWORDS)
        ]

        if not ctx.secure_score_profiles:
            return self._result(
                CheckStatus.MANUAL,
                expected="Alert policies configured for critical activities",
                actual="Secure Score profiles unavailable — manual verification required",
                notes=(
                    "Microsoft Defender portal > Policies & Rules > Alert policy\n"
                    "Verify policies exist for: Forwarding rules, Mass file downloads, "
                    "Anomalous admin activity, Suspicious email sending."
                ),
            )

        # Check the current score for alert-related controls
        passing = [p for p in alert_profiles if (p.get("controlStateUpdates") or [{}])[-1:][0].get("state", "") == "Default"]

        if alert_profiles:
            return self._result(
                CheckStatus.WARN,
                expected="Alert policies verified in Defender portal",
                actual=f"{len(alert_profiles)} alert-related Secure Score control(s) found — review recommended",
                notes=(
                    "Verify in Microsoft Defender portal > Policies & Rules > Alert policy.\n"
                    "Key alerts: mail forwarding rules, mass file downloads, anomalous sign-ins."
                ),
            )

        return self._result(
            CheckStatus.MANUAL,
            expected="Alert policies configured",
            actual="Unable to verify via API — manual check required",
            notes="Microsoft Defender portal > Policies & Rules > Alert policy.",
        )


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

LOGGING_CHECKS: list[type[BaseCheck]] = [
    CheckUnifiedAuditLog,
    CheckMailboxAuditEnabled,
    CheckAuditLogRetention,
    CheckAlertPolicies,
]
