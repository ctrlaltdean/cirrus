"""
CIS Compliance Checks — Section 3: Exchange Online

Hybrid checks: automated where DNS / Exchange Online PowerShell data is
available in PolicyContext; falls back to MANUAL with step-by-step
instructions when data cannot be collected.

DNS checks (DMARC, SPF, DKIM) require: dnspython
Exchange PS checks require: PowerShell 7 + ExchangeOnlineManagement v3
"""

from __future__ import annotations

from cirrus.compliance.base import BaseCheck, CheckResult, CheckStatus
from cirrus.compliance.context import PolicyContext


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ps_available(ctx: PolicyContext) -> bool:
    return bool(ctx.exchange_ps and ctx.exchange_ps.available)


def _dns_available(ctx: PolicyContext) -> bool:
    return bool(ctx.dns_results)


# ---------------------------------------------------------------------------
# 3.1 — Email Authentication (DKIM, DMARC, SPF)
# ---------------------------------------------------------------------------

class CheckDKIM(BaseCheck):
    """
    M365-3.1.1  DKIM signing enabled for all custom domains.
    Automated: DNS lookup for selector1/selector2._domainkey.<domain>
    Fallback: MANUAL instructions.
    """
    control_id = "M365-3.1.1"
    title = "DKIM signing enabled for all domains"
    benchmark = "CIS M365"
    level = 1
    section = "3 - Exchange Online"
    expected = "DKIM CNAME or TXT records published for selector1/selector2 on all custom domains"
    rationale = (
        "DKIM prevents email spoofing by cryptographically signing outbound "
        "messages, allowing receivers to verify authenticity."
    )
    remediation = (
        "Enable DKIM in Microsoft Defender portal > Email & Collaboration > "
        "Policies & Rules > Threat Policies > DKIM."
    )
    manual_steps = (
        "Exchange Online PowerShell:\n"
        "  1. Connect-ExchangeOnline\n"
        "  2. Get-DkimSigningConfig | Select-Object Domain, Enabled, Status\n"
        "  Expected: Enabled = True, Status = Valid for all domains\n\n"
        "DNS verification (run for each domain):\n"
        "  nslookup -type=CNAME selector1._domainkey.<yourdomain.com>\n"
        "  nslookup -type=CNAME selector2._domainkey.<yourdomain.com>"
    )
    reference = "CIS M365 v3.1 §3.1.1"

    def run(self, ctx: PolicyContext) -> CheckResult:
        # Prefer PS data (more authoritative — reflects EXO config, not just DNS)
        if _ps_available(ctx) and ctx.exchange_ps.dkim_signing_configs:
            configs = ctx.exchange_ps.dkim_signing_configs
            failing = [
                f"{c.get('Domain','?')} (Enabled={c.get('Enabled')}, Status={c.get('Status','')})"
                for c in configs
                if not c.get("Enabled") or c.get("Status", "").lower() not in ("valid", "")
            ]
            passing = [
                f"{c.get('Domain','?')} (Enabled={c.get('Enabled')}, Status={c.get('Status','')})"
                for c in configs
                if c.get("Enabled") and c.get("Status", "").lower() in ("valid", "")
            ]
            if failing:
                return self._result(
                    CheckStatus.FAIL, self.expected,
                    f"DKIM not enabled or invalid on: {', '.join(failing)}",
                )
            if passing:
                return self._result(CheckStatus.PASS, self.expected, "; ".join(passing))

        # Fall back to DNS check
        if not _dns_available(ctx):
            return self._result(
                CheckStatus.MANUAL, self.expected,
                "DNS checks unavailable — install dnspython: cirrus deps install",
                notes=self.manual_steps,
            )

        passing, failing = [], []
        for domain, dns in ctx.dns_results.items():
            if dns.error:
                continue
            if dns.dkim.is_compliant:
                passing.append(f"{domain} ({dns.dkim.status_detail})")
            else:
                failing.append(f"{domain} ({dns.dkim.status_detail})")

        checked = passing + failing
        if not checked:
            return self._result(
                CheckStatus.MANUAL, self.expected,
                "No DNS results available — verify manually",
                notes=self.manual_steps,
            )

        if failing:
            return self._result(
                CheckStatus.FAIL, self.expected,
                f"DKIM missing or misconfigured: {', '.join(failing)}",
            )
        return self._result(CheckStatus.PASS, self.expected, "; ".join(passing))


class CheckDMARC(BaseCheck):
    """
    M365-3.1.2  DMARC policy configured (p=quarantine or p=reject).
    Automated: DNS TXT lookup for _dmarc.<domain>.
    """
    control_id = "M365-3.1.2"
    title = "DMARC policy configured (p=quarantine or p=reject)"
    benchmark = "CIS M365"
    level = 1
    section = "3 - Exchange Online"
    expected = "DMARC TXT record at _dmarc.<domain> with p=quarantine or p=reject"
    rationale = (
        "DMARC instructs receiving mail servers how to handle messages that "
        "fail SPF/DKIM checks, preventing spoofing of your domain."
    )
    remediation = (
        "Publish a DMARC TXT record at _dmarc.<yourdomain.com>.\n"
        "Start with p=none, monitor reports, then advance to quarantine/reject.\n"
        "Example: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com;"
    )
    manual_steps = (
        "DNS lookup (run for each accepted domain):\n"
        "  nslookup -type=TXT _dmarc.<yourdomain.com>\n"
        "  Expected: v=DMARC1; p=quarantine;  or  v=DMARC1; p=reject;\n\n"
        "Online tool: mxtoolbox.com/dmarc.aspx\n\n"
        "Note: p=none is informational only — does NOT protect against spoofing."
    )
    reference = "CIS M365 v3.1 §3.1.2"

    def run(self, ctx: PolicyContext) -> CheckResult:
        if not _dns_available(ctx):
            return self._result(
                CheckStatus.MANUAL,
                self.expected,
                "DNS checks unavailable — install dnspython: cirrus deps install",
                notes=self.manual_steps,
            )

        passing, failing, warnings = [], [], []
        for domain, dns in ctx.dns_results.items():
            if dns.error:
                continue
            d = dns.dmarc
            if not d.found:
                failing.append(f"{domain}: no DMARC record")
            elif d.policy == "none":
                warnings.append(f"{domain}: p=none (informational only — not enforced)")
            elif d.is_compliant:
                detail = d.status_detail
                if d.pct < 100:
                    detail += f" [WARNING: pct={d.pct}% — not full enforcement]"
                passing.append(f"{domain}: {detail}")
            else:
                failing.append(f"{domain}: {d.status_detail}")

        checked = passing + failing + warnings
        if not checked:
            return self._result(
                CheckStatus.MANUAL,
                self.expected,
                "No DNS results available — verify manually",
                notes=self.manual_steps,
            )

        if failing:
            return self._result(
                CheckStatus.FAIL,
                self.expected,
                f"DMARC not enforced: {'; '.join(failing + warnings)}",
            )
        if warnings:
            return self._result(
                CheckStatus.WARN,
                self.expected,
                f"DMARC policy is p=none (not enforced): {'; '.join(warnings)}",
                notes="Advance to p=quarantine or p=reject to enforce DMARC.",
            )
        return self._result(CheckStatus.PASS, self.expected, "; ".join(passing))


class CheckSPF(BaseCheck):
    """
    M365-3.1.3  SPF record published and restrictive.
    Automated: DNS TXT lookup for <domain>.
    """
    control_id = "M365-3.1.3"
    title = "SPF record published and restrictive"
    benchmark = "CIS M365"
    level = 1
    section = "3 - Exchange Online"
    expected = "SPF TXT record ends with -all (hard fail) or ~all (soft fail)"
    rationale = (
        "SPF identifies authorized mail servers for your domain, preventing "
        "unauthorized senders from spoofing your domain."
    )
    remediation = (
        "Publish an SPF TXT record at your domain root:\n"
        "  v=spf1 include:spf.protection.outlook.com -all\n"
        "Ensure all legitimate sending services are listed before the -all."
    )
    manual_steps = (
        "DNS lookup:\n"
        "  nslookup -type=TXT <yourdomain.com>\n"
        "  Expected: v=spf1 include:spf.protection.outlook.com -all\n\n"
        "Verify all sending services are included.\n"
        "Prefer -all (hard fail) over ~all (soft fail)."
    )
    reference = "CIS M365 v3.1 §3.1.3"

    def run(self, ctx: PolicyContext) -> CheckResult:
        if not _dns_available(ctx):
            return self._result(
                CheckStatus.MANUAL,
                self.expected,
                "DNS checks unavailable — install dnspython: cirrus deps install",
                notes=self.manual_steps,
            )

        passing, failing = [], []
        for domain, dns in ctx.dns_results.items():
            if dns.error:
                continue
            s = dns.spf
            if s.is_compliant:
                mech = s.mechanism or "?"
                o365 = " [includes M365]" if s.includes_o365 else " [⚠ M365 include not detected]"
                passing.append(f"{domain}: {mech}{o365}")
            elif not s.found:
                failing.append(f"{domain}: no SPF record")
            else:
                failing.append(f"{domain}: {s.status_detail} (no -all or ~all)")

        checked = passing + failing
        if not checked:
            return self._result(
                CheckStatus.MANUAL,
                self.expected,
                "No DNS results available — verify manually",
                notes=self.manual_steps,
            )

        if failing:
            return self._result(
                CheckStatus.FAIL,
                self.expected,
                f"SPF misconfigured: {'; '.join(failing)}",
            )
        return self._result(CheckStatus.PASS, self.expected, "; ".join(passing))


# ---------------------------------------------------------------------------
# 3.2 — Anti-Phishing, Safe Links, Safe Attachments
# ---------------------------------------------------------------------------

class CheckAntiPhishingPolicy(BaseCheck):
    """
    M365-3.2.1  Anti-phishing policy with impersonation protection.
    Automated: Exchange Online PS (Get-AntiPhishPolicy).
    """
    control_id = "M365-3.2.1"
    title = "Anti-phishing policy configured (impersonation protection)"
    benchmark = "CIS M365"
    level = 1
    section = "3 - Exchange Online"
    expected = (
        "Anti-phishing policy enabled with mailbox intelligence and "
        "impersonation protection configured"
    )
    rationale = (
        "Anti-phishing policies protect against impersonation of executives, "
        "domains, and trusted senders — a primary BEC vector."
    )
    remediation = (
        "Microsoft Defender portal > Email & Collaboration > Policies & Rules > "
        "Threat Policies > Anti-phishing.\n"
        "Enable: Mailbox intelligence, Impersonation protection for users/domains."
    )
    manual_steps = (
        "Microsoft Defender portal:\n"
        "  Email & Collaboration > Policies & Rules > Threat policies > Anti-phishing\n\n"
        "Verify the default or custom policy has:\n"
        "  - Impersonation protection: Protected users (add executives)\n"
        "  - Impersonation protection: Protected domains (your domains)\n"
        "  - Mailbox intelligence: Enabled\n"
        "  - Action on impersonation: Quarantine or Move to Junk\n\n"
        "PowerShell:\n"
        "  Get-AntiPhishPolicy | Select-Object Name, Enabled, EnableTargetedUserProtection,\n"
        "    EnableMailboxIntelligence, EnableMailboxIntelligenceProtection"
    )
    reference = "CIS M365 v3.1 §3.2.1"

    def run(self, ctx: PolicyContext) -> CheckResult:
        if not _ps_available(ctx):
            ps_error = ctx.exchange_ps.error if ctx.exchange_ps else "Exchange PS not run"
            return self._result(
                CheckStatus.MANUAL,
                self.expected,
                f"Exchange Online PS unavailable: {ps_error}",
                notes=self.manual_steps,
            )

        policies = ctx.exchange_ps.anti_phish_policies
        if not policies:
            return self._result(
                CheckStatus.FAIL,
                self.expected,
                "No anti-phishing policies found",
            )

        enabled = [p for p in policies if p.get("Enabled") is True]
        if not enabled:
            return self._result(
                CheckStatus.FAIL,
                self.expected,
                f"No enabled anti-phishing policies ({len(policies)} found, all disabled)",
            )

        best = enabled[0]
        issues = []
        if not best.get("EnableMailboxIntelligence"):
            issues.append("Mailbox intelligence disabled")
        if not best.get("EnableMailboxIntelligenceProtection"):
            issues.append("Mailbox intelligence protection disabled")
        if (
            not best.get("EnableTargetedUserProtection")
            and best.get("ImpersonationProtectionState", "").lower() != "automatic"
        ):
            issues.append("User impersonation protection not fully enabled")
        if not best.get("EnableOrganizationDomainsProtection"):
            issues.append("Domain impersonation protection disabled")

        if issues:
            return self._result(
                CheckStatus.WARN,
                self.expected,
                f"Policy '{best.get('Name', '?')}' enabled but: {'; '.join(issues)}",
                notes="Review anti-phishing policy settings in Microsoft Defender portal.",
            )

        return self._result(
            CheckStatus.PASS,
            self.expected,
            f"Policy '{best.get('Name', '?')}' enabled with mailbox intelligence and impersonation protection",
        )


class CheckSafeLinks(BaseCheck):
    """
    M365-3.2.2  Safe Links policy enabled.
    Automated: Exchange Online PS (Get-SafeLinksPolicy).
    """
    control_id = "M365-3.2.2"
    title = "Safe Links policy enabled"
    benchmark = "CIS M365"
    level = 1
    section = "3 - Exchange Online"
    expected = "Safe Links enabled; URL scanning on; click-through disabled; click tracking on"
    rationale = (
        "Safe Links rewrites URLs in emails and Office documents to scan them "
        "at click time, blocking malicious links including BEC lure pages."
    )
    remediation = (
        "Microsoft Defender portal > Policies & Rules > Threat Policies > Safe Links.\n"
        "Enable: URL scanning, click tracking. Disable: Allow click-through."
    )
    manual_steps = (
        "Microsoft Defender portal:\n"
        "  Email & Collaboration > Policies & Rules > Threat policies > Safe links\n\n"
        "Verify:\n"
        "  - Policy is enabled and applied to all users\n"
        "  - 'Track user clicks' is ON\n"
        "  - 'Let users click through to original URL' is OFF\n"
        "  - URL scanning for email: ON\n"
        "  - Safe Links for Office 365 apps: ON\n\n"
        "PowerShell:\n"
        "  Get-SafeLinksPolicy | Select-Object Name, IsEnabled, ScanUrls,\n"
        "    TrackClicks, AllowClickThrough, EnableForInternalSenders"
    )
    reference = "CIS M365 v3.1 §3.2.2"

    def run(self, ctx: PolicyContext) -> CheckResult:
        if not _ps_available(ctx):
            ps_error = ctx.exchange_ps.error if ctx.exchange_ps else "Exchange PS not run"
            return self._result(
                CheckStatus.MANUAL,
                self.expected,
                f"Exchange Online PS unavailable: {ps_error}",
                notes=self.manual_steps,
            )

        policies = ctx.exchange_ps.safe_links_policies
        if not policies:
            return self._result(
                CheckStatus.FAIL,
                self.expected,
                "No Safe Links policies found",
            )

        enabled = [p for p in policies if p.get("IsEnabled") is True]
        if not enabled:
            return self._result(
                CheckStatus.FAIL,
                self.expected,
                f"No enabled Safe Links policies ({len(policies)} found, all disabled)",
            )

        best = enabled[0]
        issues = []
        if not best.get("ScanUrls"):
            issues.append("URL scanning disabled (ScanUrls=False)")
        if not best.get("TrackClicks"):
            issues.append("Click tracking disabled")
        if best.get("AllowClickThrough"):
            issues.append("Users can click through to original URL (AllowClickThrough=True)")
        if not best.get("EnableForInternalSenders"):
            issues.append("Internal sender scanning disabled")

        if issues:
            return self._result(
                CheckStatus.WARN,
                self.expected,
                f"Policy '{best.get('Name', '?')}' enabled but: {'; '.join(issues)}",
                notes="Review Safe Links settings in Microsoft Defender portal.",
            )

        return self._result(
            CheckStatus.PASS,
            self.expected,
            f"Policy '{best.get('Name', '?')}': URL scanning on, click tracking on, click-through disabled",
        )


class CheckSafeAttachments(BaseCheck):
    """
    M365-3.2.3  Safe Attachments policy enabled.
    Automated: Exchange Online PS (Get-SafeAttachmentPolicy).
    """
    control_id = "M365-3.2.3"
    title = "Safe Attachments policy enabled"
    benchmark = "CIS M365"
    level = 1
    section = "3 - Exchange Online"
    expected = "Safe Attachments enabled for all users with Block or Dynamic Delivery action"
    rationale = (
        "Safe Attachments detonates email attachments in a sandbox before "
        "delivery, blocking malware including BEC-related keyloggers and RATs."
    )
    remediation = (
        "Microsoft Defender portal > Policies & Rules > Threat Policies > Safe Attachments.\n"
        "Set action to Block or Dynamic Delivery for all users."
    )
    manual_steps = (
        "Microsoft Defender portal:\n"
        "  Email & Collaboration > Policies & Rules > Threat policies > Safe attachments\n\n"
        "Verify:\n"
        "  - Policy is enabled and applied to all users\n"
        "  - Action: Block or Dynamic Delivery (not 'Monitor' or 'Allow')\n\n"
        "PowerShell:\n"
        "  Get-SafeAttachmentPolicy | Select-Object Name, Enable, Action, ActionOnError"
    )
    reference = "CIS M365 v3.1 §3.2.3"

    GOOD_ACTIONS = {"Block", "DynamicDelivery", "Replace"}

    def run(self, ctx: PolicyContext) -> CheckResult:
        if not _ps_available(ctx):
            ps_error = ctx.exchange_ps.error if ctx.exchange_ps else "Exchange PS not run"
            return self._result(
                CheckStatus.MANUAL,
                self.expected,
                f"Exchange Online PS unavailable: {ps_error}",
                notes=self.manual_steps,
            )

        policies = ctx.exchange_ps.safe_attachments_policies
        if not policies:
            return self._result(
                CheckStatus.FAIL,
                self.expected,
                "No Safe Attachments policies found",
            )

        enabled = [p for p in policies if p.get("Enable") is True]
        if not enabled:
            return self._result(
                CheckStatus.FAIL,
                self.expected,
                f"No enabled Safe Attachments policies ({len(policies)} found)",
            )

        bad = [p for p in enabled if p.get("Action", "") not in self.GOOD_ACTIONS]
        if bad:
            bad_names = ", ".join(
                f"{p.get('Name','?')} (Action={p.get('Action','?')})" for p in bad
            )
            return self._result(
                CheckStatus.WARN,
                self.expected,
                f"Safe Attachments enabled but action is not Block/DynamicDelivery: {bad_names}",
                notes="Set Action to Block or Dynamic Delivery for full protection.",
            )

        best = enabled[0]
        return self._result(
            CheckStatus.PASS,
            self.expected,
            f"Policy '{best.get('Name', '?')}': enabled, Action={best.get('Action', '?')}",
        )


# ---------------------------------------------------------------------------
# 3.3 — Mail Flow & Forwarding
# ---------------------------------------------------------------------------

class CheckAutoExternalForwarding(BaseCheck):
    """
    M365-3.3.1  Automatic external email forwarding disabled.
    Automated: Exchange Online PS (Get-HostedOutboundSpamFilterPolicy).
    """
    control_id = "M365-3.3.1"
    title = "Automatic external email forwarding disabled"
    benchmark = "CIS M365"
    level = 1
    section = "3 - Exchange Online"
    expected = "All outbound spam policies have AutoForwardingMode = Off"
    rationale = (
        "Automatic forwarding is a primary BEC data exfiltration method. "
        "Blocking it at the transport layer prevents silent mail exfiltration."
    )
    remediation = (
        "Exchange Online PowerShell:\n"
        "  Set-HostedOutboundSpamFilterPolicy -Identity Default "
        "-AutoForwardingMode Off\n\n"
        "Or: Microsoft Defender portal > Policies > Anti-spam > "
        "Outbound spam filter policy"
    )
    manual_steps = (
        "Exchange Online PowerShell:\n"
        "  1. Connect-ExchangeOnline\n"
        "  2. Get-HostedOutboundSpamFilterPolicy | Select-Object Name, AutoForwardingMode\n"
        "  Expected: AutoForwardingMode = Off for all policies\n\n"
        "Microsoft Defender portal:\n"
        "  Email & Collaboration > Policies & Rules > Threat policies > Anti-spam\n"
        "  > Outbound spam filter policy (Default) > Forwarding rules = Off"
    )
    reference = "CIS M365 v3.1 §3.3.1"

    def run(self, ctx: PolicyContext) -> CheckResult:
        if not _ps_available(ctx):
            ps_error = ctx.exchange_ps.error if ctx.exchange_ps else "Exchange PS not run"
            return self._result(
                CheckStatus.MANUAL,
                self.expected,
                f"Exchange Online PS unavailable: {ps_error}",
                notes=self.manual_steps,
            )

        policies = ctx.exchange_ps.outbound_spam_policies
        if not policies:
            return self._result(
                CheckStatus.MANUAL,
                self.expected,
                "No outbound spam policies returned — verify manually",
                notes=self.manual_steps,
            )

        allowing = [
            p for p in policies
            if p.get("AutoForwardingMode", "").lower() not in ("off", "automatic")
        ]
        automatic = [
            p for p in policies
            if p.get("AutoForwardingMode", "").lower() == "automatic"
        ]

        if allowing:
            bad = ", ".join(
                f"{p.get('Name','?')} (AutoForwardingMode={p.get('AutoForwardingMode','?')})"
                for p in allowing
            )
            return self._result(
                CheckStatus.FAIL,
                self.expected,
                f"Forwarding allowed by: {bad}",
            )

        if automatic:
            auto_names = ", ".join(p.get("Name", "?") for p in automatic)
            return self._result(
                CheckStatus.WARN,
                self.expected,
                f"AutoForwardingMode=Automatic (not explicitly Off) on: {auto_names}",
                notes="CIS recommends explicitly setting AutoForwardingMode=Off.",
            )

        off_names = ", ".join(p.get("Name", "?") for p in policies)
        return self._result(
            CheckStatus.PASS,
            self.expected,
            f"All policies have AutoForwardingMode=Off: {off_names}",
        )


class CheckExternalSenderWarning(BaseCheck):
    """
    M365-3.3.2  External sender warning banner enabled (External In Outlook).
    Automated: Exchange Online PS (Get-ExternalInOutlook).
    """
    control_id = "M365-3.3.2"
    title = "External sender warning banner enabled"
    benchmark = "CIS M365"
    level = 1
    section = "3 - Exchange Online"
    expected = "External sender identification (External In Outlook) is enabled"
    rationale = (
        "External sender warnings reduce the effectiveness of impersonation "
        "and spear-phishing attacks by clearly marking external emails."
    )
    remediation = (
        "Exchange Online PowerShell:\n"
        "  Connect-ExchangeOnline\n"
        "  Set-ExternalInOutlook -Enabled $true"
    )
    manual_steps = (
        "Exchange Online PowerShell:\n"
        "  1. Connect-ExchangeOnline\n"
        "  2. Get-ExternalInOutlook\n"
        "  Expected: Enabled = True\n\n"
        "Exchange Admin Center:\n"
        "  Settings > Mail flow > External sender identification\n\n"
        "Note: Get-ExternalInOutlook requires ExchangeOnlineManagement module v3+"
    )
    reference = "CIS M365 v3.1 §3.3.2"

    def run(self, ctx: PolicyContext) -> CheckResult:
        if not _ps_available(ctx):
            ps_error = ctx.exchange_ps.error if ctx.exchange_ps else "Exchange PS not run"
            return self._result(
                CheckStatus.MANUAL,
                self.expected,
                f"Exchange Online PS unavailable: {ps_error}",
                notes=self.manual_steps,
            )

        eio = ctx.exchange_ps.external_in_outlook
        if not eio:
            return self._result(
                CheckStatus.MANUAL,
                self.expected,
                "ExternalInOutlook data not returned — verify manually",
                notes=self.manual_steps,
            )

        if "Error" in eio and eio["Error"]:
            return self._result(
                CheckStatus.MANUAL,
                self.expected,
                f"Get-ExternalInOutlook error: {eio['Error']}",
                notes=self.manual_steps,
            )

        enabled = eio.get("Enabled")
        if enabled is True:
            return self._result(
                CheckStatus.PASS,
                self.expected,
                "External In Outlook is enabled",
            )
        if enabled is False:
            return self._result(
                CheckStatus.FAIL,
                self.expected,
                "External In Outlook is disabled",
            )

        return self._result(
            CheckStatus.MANUAL,
            self.expected,
            "External In Outlook state unknown — verify manually",
            notes=self.manual_steps,
        )


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

EXCHANGE_CHECKS: list[type[BaseCheck]] = [
    CheckDKIM,
    CheckDMARC,
    CheckSPF,
    CheckAntiPhishingPolicy,
    CheckSafeLinks,
    CheckSafeAttachments,
    CheckAutoExternalForwarding,
    CheckExternalSenderWarning,
]
