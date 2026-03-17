"""
CIS Compliance Checks — Section 3: Exchange Online

Most Exchange controls require Exchange Online PowerShell or the
Defender portal and cannot be verified via the Graph API.
These are represented as MANUAL checks with step-by-step instructions.
"""

from __future__ import annotations

from cirrus.compliance.base import BaseCheck, CheckStatus, ManualCheck
from cirrus.compliance.context import PolicyContext

# ---------------------------------------------------------------------------
# 3.1 — Email Authentication (DKIM, DMARC, SPF)
# ---------------------------------------------------------------------------

class CheckDKIM(ManualCheck):
    control_id = "M365-3.1.1"
    title = "DKIM signing enabled for all domains"
    benchmark = "CIS M365"
    level = 1
    section = "3 - Exchange Online"
    expected = "DKIM enabled and signing key published in DNS for all accepted domains"
    rationale = "DKIM prevents email spoofing by cryptographically signing outbound messages, allowing receivers to verify authenticity."
    remediation = "Enable DKIM in Microsoft Defender portal > Email & Collaboration > Policies & Rules > Threat Policies > DKIM."
    manual_steps = (
        "Exchange Online PowerShell:\n"
        "  1. Connect-ExchangeOnline\n"
        "  2. Get-DkimSigningConfig | Select-Object Domain, Enabled, Status\n"
        "  Expected: Enabled = True, Status = Valid for all domains\n\n"
        "Or: Microsoft Defender portal > Email & collaboration > Policies & Rules\n"
        "  > Threat policies > Email authentication settings > DKIM\n\n"
        "DNS verification:\n"
        "  nslookup -type=TXT selector1._domainkey.<yourdomain.com>"
    )
    reference = "CIS M365 v3.1 §3.1.1"


class CheckDMARC(ManualCheck):
    control_id = "M365-3.1.2"
    title = "DMARC policy configured (p=quarantine or p=reject)"
    benchmark = "CIS M365"
    level = 1
    section = "3 - Exchange Online"
    expected = "DMARC TXT record published with p=quarantine or p=reject"
    rationale = "DMARC instructs receiving mail servers on how to handle messages that fail SPF and DKIM checks, preventing spoofing of your domain."
    remediation = "Publish a DMARC TXT record at _dmarc.<yourdomain.com>. Start with p=none, monitor reports, then move to quarantine/reject."
    manual_steps = (
        "DNS lookup (run for each accepted domain):\n"
        "  nslookup -type=TXT _dmarc.<yourdomain.com>\n"
        "  Expected record: v=DMARC1; p=quarantine; OR v=DMARC1; p=reject;\n\n"
        "Online tools: mxtoolbox.com/dmarc.aspx\n\n"
        "Note: p=none is informational only — does NOT protect against spoofing."
    )
    reference = "CIS M365 v3.1 §3.1.2"


class CheckSPF(ManualCheck):
    control_id = "M365-3.1.3"
    title = "SPF record published and restrictive"
    benchmark = "CIS M365"
    level = 1
    section = "3 - Exchange Online"
    expected = "SPF TXT record ends with -all (hard fail) or ~all (soft fail)"
    rationale = "SPF identifies authorized mail servers for your domain, preventing unauthorized senders from spoofing your domain."
    remediation = "Publish an SPF TXT record: v=spf1 include:spf.protection.outlook.com -all"
    manual_steps = (
        "DNS lookup:\n"
        "  nslookup -type=TXT <yourdomain.com>\n"
        "  Expected: v=spf1 include:spf.protection.outlook.com -all\n\n"
        "Verify all sending services are included in the SPF record.\n"
        "Prefer -all (hard fail) over ~all (soft fail)."
    )
    reference = "CIS M365 v3.1 §3.1.3"


# ---------------------------------------------------------------------------
# 3.2 — Anti-Phishing, Safe Links, Safe Attachments
# ---------------------------------------------------------------------------

class CheckAntiPhishingPolicy(ManualCheck):
    control_id = "M365-3.2.1"
    title = "Anti-phishing policy configured (impersonation protection)"
    benchmark = "CIS M365"
    level = 1
    section = "3 - Exchange Online"
    expected = "Anti-phishing policy enabled with impersonation protection for key users and domains"
    rationale = "Anti-phishing policies protect against impersonation of executives, domains, and trusted senders — a primary BEC vector."
    remediation = "Configure in Microsoft Defender portal > Policies & Rules > Threat Policies > Anti-phishing."
    manual_steps = (
        "Microsoft Defender portal:\n"
        "  Email & Collaboration > Policies & Rules > Threat policies > Anti-phishing\n\n"
        "Verify the default or custom policy has:\n"
        "  - Impersonation protection: Protected users (add executives)\n"
        "  - Impersonation protection: Protected domains (your domains)\n"
        "  - Mailbox intelligence: Enabled\n"
        "  - Action on impersonation: Quarantine or Move to Junk\n\n"
        "PowerShell:\n"
        "  Get-AntiPhishPolicy | Select-Object Name, Enabled, EnableTargetedUserProtection\n"
        "  Get-AntiPhishPolicy | Select-Object Name, EnableMailboxIntelligence"
    )
    reference = "CIS M365 v3.1 §3.2.1"


class CheckSafeLinks(ManualCheck):
    control_id = "M365-3.2.2"
    title = "Safe Links policy enabled"
    benchmark = "CIS M365"
    level = 1
    section = "3 - Exchange Online"
    expected = "Safe Links enabled for email and Office apps; click-tracking enabled"
    rationale = "Safe Links rewrites URLs in emails and Office documents to scan them at click time, blocking malicious links including BEC lure pages."
    remediation = "Enable in Microsoft Defender portal > Policies & Rules > Threat Policies > Safe Links."
    manual_steps = (
        "Microsoft Defender portal:\n"
        "  Email & Collaboration > Policies & Rules > Threat policies > Safe links\n\n"
        "Verify:\n"
        "  - Policy is enabled and applied to all users\n"
        "  - 'Track user clicks' is enabled\n"
        "  - 'Let users click through to original URL' is DISABLED\n"
        "  - Safe links for Office 365 apps: Enabled\n\n"
        "PowerShell:\n"
        "  Get-SafeLinksPolicy | Select-Object Name, IsEnabled, TrackClicks, AllowClickThrough"
    )
    reference = "CIS M365 v3.1 §3.2.2"


class CheckSafeAttachments(ManualCheck):
    control_id = "M365-3.2.3"
    title = "Safe Attachments policy enabled"
    benchmark = "CIS M365"
    level = 1
    section = "3 - Exchange Online"
    expected = "Safe Attachments enabled for all users with Block or Dynamic Delivery action"
    rationale = "Safe Attachments detonates email attachments in a sandbox before delivery, blocking malware including BEC-related keyloggers and RATs."
    remediation = "Enable in Microsoft Defender portal > Policies & Rules > Threat Policies > Safe Attachments."
    manual_steps = (
        "Microsoft Defender portal:\n"
        "  Email & Collaboration > Policies & Rules > Threat policies > Safe attachments\n\n"
        "Verify:\n"
        "  - Policy is enabled and applied to all users\n"
        "  - Action: Block or Dynamic Delivery (not 'Monitor' or 'Off')\n"
        "  - Enable redirect for blocked attachments: Enabled (set to security inbox)\n\n"
        "PowerShell:\n"
        "  Get-SafeAttachmentPolicy | Select-Object Name, Enable, Action"
    )
    reference = "CIS M365 v3.1 §3.2.3"


# ---------------------------------------------------------------------------
# 3.3 — Mail Flow & Forwarding
# ---------------------------------------------------------------------------

class CheckAutoExternalForwarding(ManualCheck):
    control_id = "M365-3.3.1"
    title = "Automatic external email forwarding disabled"
    benchmark = "CIS M365"
    level = 1
    section = "3 - Exchange Online"
    expected = "Outbound spam policy blocks automatic forwarding to external domains"
    rationale = "Automatic forwarding is a primary BEC data exfiltration method. Blocking it at the transport layer prevents silent mail exfiltration."
    remediation = (
        "Exchange Online PowerShell:\n"
        "  Set-HostedOutboundSpamFilterPolicy -Identity Default -AutoForwardingMode Off\n\n"
        "Or: Microsoft Defender portal > Policies > Anti-spam > Outbound spam filter policy"
    )
    manual_steps = (
        "Exchange Online PowerShell:\n"
        "  1. Connect-ExchangeOnline\n"
        "  2. Get-HostedOutboundSpamFilterPolicy | Select-Object Name, AutoForwardingMode\n"
        "  Expected: AutoForwardingMode = Off (for default and all custom policies)\n\n"
        "Microsoft Defender portal:\n"
        "  Email & Collaboration > Policies & Rules > Threat policies > Anti-spam\n"
        "  > Outbound spam filter policy (Default) > Edit\n"
        "  > Forwarding rules: Automatic forwarding rules = Off"
    )
    reference = "CIS M365 v3.1 §3.3.1"


class CheckExternalSenderWarning(ManualCheck):
    control_id = "M365-3.3.2"
    title = "External sender warning banner enabled"
    benchmark = "CIS M365"
    level = 1
    section = "3 - Exchange Online"
    expected = "External sender banner displayed on inbound emails from outside the organization"
    rationale = "External sender warnings reduce the effectiveness of impersonation and spear-phishing attacks by clearly marking external emails."
    remediation = (
        "Exchange Admin Center > Mail flow > Rules: Create a rule to prepend "
        "'[EXTERNAL]' to subject, or enable the built-in external tag.\n\n"
        "Or via PowerShell: Set-ExternalInOutlook -Enabled $true"
    )
    manual_steps = (
        "Exchange Online PowerShell:\n"
        "  1. Connect-ExchangeOnline\n"
        "  2. Get-ExternalInOutlook\n"
        "  Expected: Enabled = True\n\n"
        "Or check Exchange Admin Center:\n"
        "  Settings > Mail flow > External sender identification\n\n"
        "Note: Get-ExternalInOutlook requires Exchange Online module v3+"
    )
    reference = "CIS M365 v3.1 §3.3.2"


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
