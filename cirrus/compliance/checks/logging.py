"""
CIS Compliance Checks — Section 6: Logging & Monitoring

Mix of automated (Graph API) and manual (Exchange PowerShell) checks.
"""

from __future__ import annotations

from cirrus.compliance.base import BaseCheck, CheckResult, CheckStatus, ManualCheck
from cirrus.compliance.context import PolicyContext


class CheckUnifiedAuditLog(BaseCheck):
    """
    M365-6.1.1  Unified Audit Log search is enabled.
    Automated: uses UnifiedAuditLogIngestionEnabled from Exchange Online org config (PS batch).
    Fallback: MANUAL instructions.
    """
    control_id = "M365-6.1.1"
    title = "Unified Audit Log search is enabled"
    benchmark = "CIS M365"
    level = 1
    section = "6 - Logging & Monitoring"
    expected = "UnifiedAuditLogIngestionEnabled = True"
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

    def run(self, ctx: PolicyContext) -> CheckResult:
        ps = ctx.exchange_ps
        if not ps or not ps.available:
            ps_error = ps.error if ps else "Exchange PS not run"
            return self._result(
                CheckStatus.MANUAL, self.expected,
                f"Exchange Online PS unavailable: {ps_error}",
                notes=self.manual_steps,
            )

        alc = ps.admin_audit_log_config
        if not alc or "Error" in alc:
            err = alc.get("Error", "no data") if alc else "not returned"
            return self._result(
                CheckStatus.MANUAL, self.expected,
                f"Get-AdminAuditLogConfig unavailable: {err}",
                notes=self.manual_steps,
            )

        ual_enabled = alc.get("UnifiedAuditLogIngestionEnabled")
        if ual_enabled is True:
            return self._result(CheckStatus.PASS, self.expected, "UnifiedAuditLogIngestionEnabled = True")
        if ual_enabled is False:
            return self._result(CheckStatus.FAIL, self.expected, "UnifiedAuditLogIngestionEnabled = False — UAL is disabled")

        return self._result(
            CheckStatus.MANUAL, self.expected,
            "UnifiedAuditLogIngestionEnabled state unknown — verify manually",
            notes=self.manual_steps,
        )


class CheckMailboxAuditEnabled(BaseCheck):
    """
    M365-6.1.2  Mailbox auditing enabled for all users.
    Automated: uses AuditDisabled from Exchange Online org config (PS batch).
    Fallback: MANUAL instructions.
    """
    control_id = "M365-6.1.2"
    title = "Mailbox auditing enabled for all users"
    benchmark = "CIS M365"
    level = 1
    section = "6 - Logging & Monitoring"
    expected = "Org-level AuditDisabled = False (mailbox auditing on for all mailboxes)"
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

    def run(self, ctx: PolicyContext) -> CheckResult:
        ps = ctx.exchange_ps
        if not ps or not ps.available:
            ps_error = ps.error if ps else "Exchange PS not run"
            return self._result(
                CheckStatus.MANUAL,
                self.expected,
                f"Exchange Online PS unavailable: {ps_error}",
                notes=self.manual_steps,
            )

        org_config = ps.org_config
        if not org_config:
            return self._result(
                CheckStatus.MANUAL,
                self.expected,
                "Org config not returned from PS — verify manually",
                notes=self.manual_steps,
            )

        audit_disabled = org_config.get("AuditDisabled")
        if audit_disabled is False:
            return self._result(
                CheckStatus.PASS,
                self.expected,
                "AuditDisabled = False — org-level mailbox auditing is enabled",
            )
        if audit_disabled is True:
            return self._result(
                CheckStatus.FAIL,
                self.expected,
                "AuditDisabled = True — mailbox auditing is disabled at org level",
            )

        return self._result(
            CheckStatus.MANUAL,
            self.expected,
            "AuditDisabled state unknown — verify manually",
            notes=self.manual_steps,
        )


class CheckAuditLogRetention(BaseCheck):
    """
    M365-6.1.3  Audit log retention at least 90 days (1 year recommended).
    Automated: uses audit_retention_policies from IPPS batch (via EXO module).
    Fallback: MANUAL instructions.
    """
    control_id = "M365-6.1.3"
    title = "Audit log retention is at least 90 days (1 year recommended)"
    benchmark = "CIS M365"
    level = 2
    section = "6 - Logging & Monitoring"
    expected = "Audit log retention policy with RetentionDuration >= ThreeMonths (OneYear recommended)"
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
        "  Expected: RetentionDuration >= OneYear\n\n"
        "License note: E1=90 days default; E3=1 year; E5/Compliance add-on=up to 10 years"
    )
    reference = "CIS M365 v3.1 §6.1.3"

    # RetentionDuration values from highest to lowest
    GOOD_DURATIONS = {"TenYears", "SevenYears", "FiveYears", "ThreeYears", "OneYear"}
    WARN_DURATIONS = {"SixMonths", "ThreeMonths", "OneMonth"}

    def run(self, ctx: PolicyContext) -> CheckResult:
        ps = ctx.exchange_ps
        if not ps or not ps.available:
            ps_error = ps.error if ps else "Exchange PS not run"
            return self._result(
                CheckStatus.MANUAL, self.expected,
                f"Exchange Online PS unavailable: {ps_error}",
                notes=self.manual_steps,
            )

        policies = ps.audit_retention_policies
        if not policies:
            return self._result(
                CheckStatus.MANUAL, self.expected,
                "No audit retention policies returned (IPPS may not be accessible or no policies configured)",
                notes=self.manual_steps,
            )

        # Check if any policy has an error
        if len(policies) == 1 and ("Error" in policies[0] or "ConnectError" in policies[0]):
            err = policies[0].get("Error") or policies[0].get("ConnectError", "unknown error")
            return self._result(
                CheckStatus.MANUAL, self.expected,
                f"IPPS connection unavailable: {err}",
                notes=self.manual_steps,
            )

        good = [p for p in policies if p.get("RetentionDuration") in self.GOOD_DURATIONS]
        warn = [p for p in policies if p.get("RetentionDuration") in self.WARN_DURATIONS]

        if good:
            best = max(good, key=lambda p: list(self.GOOD_DURATIONS).index(p.get("RetentionDuration", "OneYear")) if p.get("RetentionDuration") in self.GOOD_DURATIONS else 99)
            return self._result(
                CheckStatus.PASS, self.expected,
                f"{len(good)} policy/policies with ≥1 year retention. Best: '{best.get('Name','?')}' ({best.get('RetentionDuration','?')})",
            )

        if warn:
            durations = ", ".join(f"{p.get('Name','?')}={p.get('RetentionDuration','?')}" for p in warn)
            return self._result(
                CheckStatus.WARN, self.expected,
                f"Retention policies found but below 1 year: {durations}",
                notes="CIS recommends at least 1 year retention. E3/E5 provide 1-year default.",
            )

        return self._result(
            CheckStatus.MANUAL, self.expected,
            f"{len(policies)} retention policy/policies found but retention duration not recognized — verify manually",
            notes=self.manual_steps,
        )


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
