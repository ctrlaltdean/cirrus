"""
cirrus.analysis.scan — Email security posture scanning.

Three operational tiers:
  Tier 1 (DNS)    — Passive SPF/DMARC/DKIM/MX checks. No authentication.
  Tier 2 (SMTP)   — Unauthenticated SMTP probing of tenant MX. TCP port 25.
  Tier 3 (Tenant) — Authenticated Exchange Online audit via PowerShell.

All tiers produce ScanFinding objects in a common schema so findings can
be aggregated across tiers for a unified report.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import dns.exception
import dns.resolver

from cirrus.utils.helpers import utc_now

# ── Severity ordering (lower index = higher severity) ────────────────────────

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "info": 3}


def _sev_rank(s: str) -> int:
    return _SEVERITY_ORDER.get(s.lower(), 99)


# ─────────────────────────────────────────────────────────────────────────────
# Data Model
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ScanFinding:
    """A single finding produced by any scan tier."""
    domain: str
    severity: str           # "critical" | "high" | "medium" | "info"
    category: str           # "spf" | "dmarc" | "dkim" | "mx" | "smtp" | "tenant"
    finding: str            # short title (≤ 100 chars)
    detail: str             # human-readable explanation / evidence
    remediation: str = ""   # specific actionable guidance (populated for critical/high)
    references: list[str] = field(default_factory=list)
    source: str = ""        # which internal check produced this
    timestamp: str = field(default_factory=utc_now)


@dataclass
class ScanReport:
    """Aggregated findings from one or more scan tiers."""
    domains: list[str]
    generated_at: str
    findings: list[ScanFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def by_severity(self) -> dict[str, list[ScanFinding]]:
        buckets: dict[str, list[ScanFinding]] = {s: [] for s in _SEVERITY_ORDER}
        for f in self.findings:
            buckets.setdefault(f.severity, []).append(f)
        return buckets

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    @property
    def sorted_findings(self) -> list[ScanFinding]:
        return sorted(self.findings, key=lambda f: (_sev_rank(f.severity), f.domain, f.category))

    def to_records(self) -> list[dict[str, Any]]:
        """Flat dicts suitable for CSV/JSON export."""
        return [
            {
                "Timestamp": f.timestamp,
                "Domain": f.domain,
                "Severity": f.severity.upper(),
                "Category": f.category,
                "Finding": f.finding,
                "Detail": f.detail,
                "Remediation": f.remediation,
                "References": "; ".join(f.references),
                "Source": f.source,
            }
            for f in self.sorted_findings
        ]


# ─────────────────────────────────────────────────────────────────────────────
# Tier 1 — Passive DNS Checks
# ─────────────────────────────────────────────────────────────────────────────

_RESOLVER = dns.resolver.Resolver()
_RESOLVER.lifetime = 5.0


def _txt_records(name: str) -> list[str]:
    try:
        answers = _RESOLVER.resolve(name, "TXT")
        return [b"".join(r.strings).decode("utf-8", errors="replace") for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return []
    except Exception:
        return []


def _cname_record(name: str) -> str | None:
    try:
        answers = _RESOLVER.resolve(name, "CNAME")
        return str(answers[0].target).rstrip(".")
    except Exception:
        return None


def _mx_records(name: str) -> list[tuple[int, str]]:
    try:
        answers = _RESOLVER.resolve(name, "MX")
        return sorted((r.preference, str(r.exchange).rstrip(".")) for r in answers)
    except Exception:
        return []


# ── SPF ───────────────────────────────────────────────────────────────────────

_RISKY_INCLUDES: dict[str, str] = {
    "sendgrid.net": "SendGrid",
    "spf.protection.outlook.com": "Microsoft EOP (shared across all M365 tenants)",
    "protection.outlook.com": "Microsoft EOP (shared across all M365 tenants)",
    "amazonses.com": "Amazon SES",
    "amazonaws.com": "Amazon AWS (SES/EC2)",
    "mailgun.org": "Mailgun",
    "sparkpostmail.com": "SparkPost",
    "sp.mtasv.net": "SparkPost (legacy)",
}


def _count_dns_lookups(spf: str) -> int:
    return len(re.findall(r"(?:include|a|mx|ptr|exists):", spf, re.IGNORECASE))


def _check_spf(domain: str) -> tuple[list[ScanFinding], str | None]:
    findings: list[ScanFinding] = []
    try:
        txt_records = _txt_records(domain)
        spf_records = [r for r in txt_records if r.lower().startswith("v=spf1")]

        if not spf_records:
            findings.append(ScanFinding(
                domain=domain, severity="critical", category="spf",
                finding="SPF record missing",
                detail=(
                    f"No SPF TXT record found at {domain}. Any IP address can send mail "
                    f"claiming to be from {domain} and pass SPF evaluation."
                ),
                remediation=(
                    f"Publish a TXT record at {domain}: "
                    f"'v=spf1 include:<your-sending-infrastructure> -all'. "
                    "Start with -all (HardFail) to reject unauthorized senders."
                ),
                references=[
                    "https://www.rfc-editor.org/rfc/rfc7208",
                    "https://learn.microsoft.com/en-us/microsoft-365/admin/email/set-up-spf-in-office-365-help-to-prevent-spoofing",
                ],
                source="_check_spf",
            ))
            return findings, None

        if len(spf_records) > 1:
            findings.append(ScanFinding(
                domain=domain, severity="high", category="spf",
                finding=f"Multiple SPF records ({len(spf_records)})",
                detail=(
                    f"Found {len(spf_records)} SPF TXT records. RFC 7208 §3.2 requires exactly one. "
                    "Most senders select one arbitrarily, causing inconsistent authentication results."
                ),
                remediation="Merge all SPF records into a single TXT record at the domain root.",
                references=["https://www.rfc-editor.org/rfc/rfc7208#section-3.2"],
                source="_check_spf",
            ))

        spf = spf_records[0]
        spf_lower = spf.lower()

        if "+all" in spf_lower:
            findings.append(ScanFinding(
                domain=domain, severity="critical", category="spf",
                finding="SPF +all: every IP address authorized to send",
                detail=(
                    f"SPF record contains '+all', authorizing every IP address to send "
                    f"mail as {domain}. SPF provides no spoofing protection."
                ),
                remediation="Replace '+all' with '-all' to hard-fail unauthorized senders.",
                references=["https://www.rfc-editor.org/rfc/rfc7208#section-5.1"],
                source="_check_spf",
            ))
        elif "~all" in spf_lower:
            findings.append(ScanFinding(
                domain=domain, severity="high", category="spf",
                finding="SPF ~all (SoftFail): enforcement not active",
                detail=(
                    f"SPF record ends with '~all' (SoftFail). Unauthorized senders are tagged "
                    f"but not rejected. Many receivers treat SoftFail identically to Pass."
                ),
                remediation=(
                    "Transition to '-all' (HardFail) once all legitimate sending sources are "
                    "enumerated. Pair with DMARC p=quarantine or p=reject to enforce failures."
                ),
                references=["https://www.rfc-editor.org/rfc/rfc7208#section-8.5"],
                source="_check_spf",
            ))
        elif "?all" in spf_lower:
            findings.append(ScanFinding(
                domain=domain, severity="high", category="spf",
                finding="SPF ?all (Neutral): no policy",
                detail=(
                    f"SPF record ends with '?all' (Neutral), equivalent to having no SPF policy. "
                    "Receivers treat unauthorized senders neither as passing nor failing."
                ),
                remediation=(
                    "Replace '?all' with '-all'. Enumerate all legitimate sending infrastructure "
                    "using include: mechanisms before switching."
                ),
                references=["https://www.rfc-editor.org/rfc/rfc7208#section-8.6"],
                source="_check_spf",
            ))

        lookup_count = _count_dns_lookups(spf)
        if lookup_count >= 10:
            findings.append(ScanFinding(
                domain=domain, severity="critical", category="spf",
                finding=f"SPF DNS lookup limit exceeded ({lookup_count}/10) — Permerror",
                detail=(
                    f"SPF requires {lookup_count} DNS lookups. RFC 7208 caps evaluation at 10. "
                    "Exceeding the limit results in Permerror; many receivers treat this as "
                    "a fail or neutral, defeating SPF enforcement."
                ),
                remediation=(
                    "Flatten SPF by resolving include: chains and replacing them with direct "
                    "ip4:/ip6: mechanisms. Tools: dmarcian SPF surveyor, mxtoolbox SPF checker."
                ),
                references=["https://www.rfc-editor.org/rfc/rfc7208#section-4.6.4"],
                source="_check_spf",
            ))
        elif lookup_count >= 8:
            findings.append(ScanFinding(
                domain=domain, severity="high", category="spf",
                finding=f"SPF approaching DNS lookup limit ({lookup_count}/10)",
                detail=(
                    f"SPF requires {lookup_count} DNS lookups. RFC 7208 caps this at 10. "
                    "Adding any new include: mechanism may push the record into Permerror."
                ),
                remediation=(
                    "Flatten SPF includes to ip4:/ip6: mechanisms before adding new sending "
                    "infrastructure. Target ≤ 5 lookups for headroom."
                ),
                references=["https://www.rfc-editor.org/rfc/rfc7208#section-4.6.4"],
                source="_check_spf",
            ))

        for pattern, service_name in _RISKY_INCLUDES.items():
            if pattern in spf_lower:
                findings.append(ScanFinding(
                    domain=domain, severity="medium", category="spf",
                    finding=f"SPF includes shared infrastructure: {service_name}",
                    detail=(
                        f"SPF includes '{pattern}' ({service_name}). Any customer of this "
                        f"shared sending platform can send mail that passes SPF for {domain} "
                        "if they use the same service — the SPF pass cannot be attributed "
                        "exclusively to your organization."
                    ),
                    remediation=(
                        f"Evaluate whether {service_name} is legitimately used for outbound mail. "
                        "Supplement with DMARC p=reject to require DKIM alignment in addition to SPF, "
                        "so a shared-infrastructure SPF pass alone is insufficient."
                    ),
                    references=["https://www.rfc-editor.org/rfc/rfc7208"],
                    source="_check_spf",
                ))

        # Surface the record itself as INFO if no critical issues
        if not any(f.severity == "critical" for f in findings if f.category == "spf"):
            findings.append(ScanFinding(
                domain=domain, severity="info", category="spf",
                finding="SPF record present",
                detail=f"Record: {spf}. DNS lookup mechanisms used: {lookup_count}.",
                source="_check_spf",
            ))

        return findings, None
    except Exception as exc:
        return findings, f"spf/{domain}: {exc}"


# ── DMARC ─────────────────────────────────────────────────────────────────────

def _parse_dmarc_tags(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip().lower()] = v.strip().lower()
    return tags


def _check_dmarc(domain: str) -> tuple[list[ScanFinding], str | None]:
    findings: list[ScanFinding] = []
    try:
        dmarc_name = f"_dmarc.{domain}"
        txt_records = _txt_records(dmarc_name)
        dmarc_records = [r for r in txt_records if r.lower().startswith("v=dmarc1")]

        if not dmarc_records:
            findings.append(ScanFinding(
                domain=domain, severity="critical", category="dmarc",
                finding="DMARC record missing",
                detail=(
                    f"No DMARC TXT record at _dmarc.{domain}. Authentication failures "
                    "(SPF/DKIM mismatches) generate no enforcement action and no reports. "
                    "Spoofed mail will be delivered."
                ),
                remediation=(
                    f"Publish a TXT record at _dmarc.{domain}: "
                    f"'v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@{domain}'. "
                    "Start with p=quarantine, review aggregate reports, then advance to p=reject."
                ),
                references=[
                    "https://www.rfc-editor.org/rfc/rfc7489",
                    "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/use-dmarc-to-validate-email",
                ],
                source="_check_dmarc",
            ))
            return findings, None

        dmarc = dmarc_records[0]
        tags = _parse_dmarc_tags(dmarc)
        policy = tags.get("p", "none")

        if policy == "none":
            findings.append(ScanFinding(
                domain=domain, severity="critical", category="dmarc",
                finding="DMARC p=none: monitoring only, no enforcement",
                detail=(
                    f"DMARC policy is p=none. Authentication failures are only logged "
                    "(if rua= is configured) — no mail is quarantined or rejected. "
                    "Spoofed mail is delivered."
                ),
                remediation=(
                    f"Transition to p=quarantine: update _dmarc.{domain} to 'p=quarantine'. "
                    "Configure rua= to receive aggregate reports first. Once legitimate mail "
                    "flows cleanly, advance to p=reject."
                ),
                references=["https://www.rfc-editor.org/rfc/rfc7489#section-6.3"],
                source="_check_dmarc",
            ))
        elif policy == "quarantine":
            findings.append(ScanFinding(
                domain=domain, severity="medium", category="dmarc",
                finding="DMARC p=quarantine: partial enforcement (junk, not reject)",
                detail=(
                    "DMARC quarantine policy routes failing mail to junk/spam rather than "
                    "rejecting it. Spoofed mail may still be read by recipients."
                ),
                remediation=(
                    f"Advance to p=reject: update _dmarc.{domain} to 'p=reject'. "
                    "Review aggregate reports (rua=) to confirm no legitimate mail is failing "
                    "DMARC before escalating."
                ),
                references=["https://www.rfc-editor.org/rfc/rfc7489#section-6.3"],
                source="_check_dmarc",
            ))
        elif policy == "reject":
            findings.append(ScanFinding(
                domain=domain, severity="info", category="dmarc",
                finding="DMARC p=reject: full enforcement active",
                detail=f"DMARC rejects authentication failures. Record: {dmarc}",
                source="_check_dmarc",
            ))

        aspf = tags.get("aspf", "r")
        adkim = tags.get("adkim", "r")
        if aspf == "r":
            findings.append(ScanFinding(
                domain=domain, severity="medium", category="dmarc",
                finding="DMARC aspf=relaxed (default): subdomain spoofing passes SPF alignment",
                detail=(
                    "SPF alignment is relaxed: the SPF-authenticated domain only needs to share "
                    "the organizational domain with the From: header. Subdomain spoofing "
                    "(e.g., attacker@sub.contoso.com From: contoso.com) passes SPF alignment."
                ),
                remediation=(
                    f"Set aspf=s (strict) if mail only flows from exact From: domain matches. "
                    f"Update _dmarc.{domain}: add 'aspf=s;'"
                ),
                references=["https://www.rfc-editor.org/rfc/rfc7489#section-3.1"],
                source="_check_dmarc",
            ))
        if adkim == "r":
            findings.append(ScanFinding(
                domain=domain, severity="medium", category="dmarc",
                finding="DMARC adkim=relaxed (default): subdomain DKIM signing passes alignment",
                detail=(
                    "DKIM alignment is relaxed: the signing domain (d=) only needs to match "
                    "the organizational domain of the From: header. Subdomain mismatch still passes."
                ),
                remediation=(
                    f"Set adkim=s (strict): the DKIM d= must exactly match the From: header domain. "
                    f"Update _dmarc.{domain}: add 'adkim=s;'"
                ),
                references=["https://www.rfc-editor.org/rfc/rfc7489#section-3.1"],
                source="_check_dmarc",
            ))

        rua = tags.get("rua", "")
        ruf = tags.get("ruf", "")
        if not rua:
            findings.append(ScanFinding(
                domain=domain, severity="medium", category="dmarc",
                finding="DMARC rua= missing: no aggregate reporting",
                detail=(
                    f"No aggregate report URI in DMARC record. Spoofing attempts against "
                    f"{domain} produce no visibility for the domain owner."
                ),
                remediation=(
                    f"Add rua=mailto:dmarc-reports@{domain} (or a third-party DMARC reporting "
                    f"service) to _dmarc.{domain}."
                ),
                references=["https://www.rfc-editor.org/rfc/rfc7489#section-7.2"],
                source="_check_dmarc",
            ))
        else:
            findings.append(ScanFinding(
                domain=domain, severity="info", category="dmarc",
                finding="DMARC aggregate reporting configured",
                detail=f"Aggregate reports sent to: {rua}",
                source="_check_dmarc",
            ))

        if not ruf:
            findings.append(ScanFinding(
                domain=domain, severity="info", category="dmarc",
                finding="DMARC ruf= missing: no forensic reports",
                detail=(
                    "No forensic reporting URI configured. Forensic reports contain individual "
                    "failure samples. (Many receiving MTAs omit ruf= support regardless.)"
                ),
                source="_check_dmarc",
            ))

        return findings, None
    except Exception as exc:
        return findings, f"dmarc/{domain}: {exc}"


# ── DKIM ──────────────────────────────────────────────────────────────────────

_DKIM_SELECTORS = [
    "selector1", "selector2",          # M365 defaults
    "google",                           # Google Workspace
    "k1", "k2",                         # Klaviyo, common generic
    "smtp", "dkim", "mail", "email",
    "s1", "s2", "key1", "key2",
    "default", "mailjet", "sendgrid",
]


def _estimate_key_bits(dkim_record: str) -> int | None:
    """Estimate RSA key bit length from DER byte length of the p= base64 value."""
    import base64
    m = re.search(r"p=([A-Za-z0-9+/=]+)", dkim_record)
    if not m:
        return None
    try:
        der = base64.b64decode(m.group(1) + "==")
        if len(der) > 270:
            return 2048
        if len(der) > 140:
            return 1024
        return None
    except Exception:
        return None


def _check_dkim(domain: str, is_m365: bool = False) -> tuple[list[ScanFinding], str | None]:
    findings: list[ScanFinding] = []
    found: list[str] = []

    try:
        for selector in _DKIM_SELECTORS:
            dkim_name = f"{selector}._domainkey.{domain}"
            txt_records = _txt_records(dkim_name)
            cname = _cname_record(dkim_name)
            dkim_txt = next(
                (r for r in txt_records if "v=dkim1" in r.lower() or "p=" in r.lower()),
                None,
            )

            if dkim_txt or cname:
                found.append(selector)
                key_bits = _estimate_key_bits(dkim_txt) if dkim_txt else None
                parts = [f"selector {selector}._domainkey.{domain}"]
                if cname:
                    parts.append(f"CNAME → {cname}")
                if key_bits:
                    parts.append(f"{key_bits}-bit RSA")
                findings.append(ScanFinding(
                    domain=domain, severity="info", category="dkim",
                    finding=f"DKIM selector active: {selector}",
                    detail="; ".join(parts),
                    source="_check_dkim",
                ))
                if key_bits and key_bits < 2048:
                    findings.append(ScanFinding(
                        domain=domain, severity="medium", category="dkim",
                        finding=f"DKIM selector '{selector}': weak key ({key_bits}-bit)",
                        detail=(
                            f"Selector '{selector}' uses a {key_bits}-bit RSA key. "
                            "Keys below 2048 bits are considered weak and may be cryptographically compromised."
                        ),
                        remediation=(
                            f"Rotate to a 2048-bit key. For M365: "
                            f"Rotate-DkimSigningConfig -KeySize 2048 -Identity {domain}"
                        ),
                        references=[
                            "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/use-dkim-to-validate-outbound-email"
                        ],
                        source="_check_dkim",
                    ))

        # M365: selector1 / selector2 CNAME structure specifically
        if is_m365:
            for sel in ("selector1", "selector2"):
                cname = _cname_record(f"{sel}._domainkey.{domain}")
                if not cname:
                    findings.append(ScanFinding(
                        domain=domain, severity="high", category="dkim",
                        finding=f"M365 DKIM {sel} CNAME missing — signing disabled for {domain}",
                        detail=(
                            f"For M365-hosted domains, {sel}._domainkey.{domain} must be a CNAME "
                            "pointing to *.domainkey.*.onmicrosoft.com. The missing CNAME means "
                            "DKIM signing is disabled in the tenant for this domain."
                        ),
                        remediation=(
                            f"Enable DKIM signing: in Microsoft 365 Defender portal → Email & "
                            f"Collaboration → Policies & Rules → DKIM. Or via PowerShell: "
                            f"New-DkimSigningConfig -DomainName {domain} -Enabled $true, "
                            "then add the CNAME records provided."
                        ),
                        references=[
                            "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/use-dkim-to-validate-outbound-email"
                        ],
                        source="_check_dkim",
                    ))
                elif ".onmicrosoft.com" not in cname.lower():
                    findings.append(ScanFinding(
                        domain=domain, severity="medium", category="dkim",
                        finding=f"M365 DKIM {sel}: CNAME target unexpected",
                        detail=(
                            f"{sel}._domainkey.{domain} → {cname} "
                            "(expected *.domainkey.*.onmicrosoft.com pattern for M365)."
                        ),
                        source="_check_dkim",
                    ))

        if not found:
            findings.append(ScanFinding(
                domain=domain, severity="high", category="dkim",
                finding=f"No DKIM selectors found for {domain}",
                detail=(
                    f"None of the {len(_DKIM_SELECTORS)} probed selectors returned a DKIM record. "
                    "Outbound mail from this domain is likely not DKIM-signed, undermining "
                    "DMARC authentication (which requires SPF or DKIM alignment)."
                ),
                remediation=(
                    "Configure DKIM signing for all outbound mail streams. "
                    "For M365: enable in Microsoft 365 Defender portal → DKIM settings."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/use-dkim-to-validate-outbound-email"
                ],
                source="_check_dkim",
            ))

        return findings, None
    except Exception as exc:
        return findings, f"dkim/{domain}: {exc}"


# ── MX Fingerprinting ─────────────────────────────────────────────────────────

_SEG_PATTERNS: dict[str, str] = {
    "pphosted.com": "Proofpoint",
    "ppe-hosted.com": "Proofpoint (hosted)",
    "mimecast.com": "Mimecast",
    "mimecast.org": "Mimecast",
    "barracudanetworks.com": "Barracuda",
    "hydra.sophos.com": "Sophos Email Security",
    "messagelabs.com": "Broadcom/Symantec Email Security",
}


def _fingerprint_mx(domain: str) -> tuple[list[ScanFinding], str | None, str | None, bool]:
    """
    Returns: (findings, error, tenant_mx_host, is_m365)
    tenant_mx_host is the *.mail.protection.outlook.com hostname if M365, else None.
    """
    findings: list[ScanFinding] = []
    tenant_mx: str | None = None
    is_m365 = False

    try:
        mx_records = _mx_records(domain)
        if not mx_records:
            findings.append(ScanFinding(
                domain=domain, severity="info", category="mx",
                finding="No MX records found",
                detail=f"DNS returned no MX records for {domain}.",
                source="_fingerprint_mx",
            ))
            return findings, None, tenant_mx, is_m365

        mx_hosts = [h for _, h in mx_records]

        # M365 detection
        m365_hosts = [h for h in mx_hosts if "mail.protection.outlook.com" in h.lower()]
        if m365_hosts:
            is_m365 = True
            tenant_mx = m365_hosts[0]
            findings.append(ScanFinding(
                domain=domain, severity="info", category="mx",
                finding="MX: Microsoft 365 Exchange Online Protection",
                detail=(
                    f"Primary MX → {tenant_mx}. "
                    f"Direct-send (Tier 2 probe) target: {tenant_mx}"
                ),
                source="_fingerprint_mx",
            ))
        else:
            findings.append(ScanFinding(
                domain=domain, severity="info", category="mx",
                finding=f"MX: non-M365 ({mx_hosts[0]})",
                detail=(
                    f"MX records: {', '.join(mx_hosts)}. "
                    "Tier 2 SMTP probing is designed for M365 EOP targets; "
                    "some checks may not apply to other MTAs."
                ),
                source="_fingerprint_mx",
            ))

        # SEG detection
        for pattern, seg_name in _SEG_PATTERNS.items():
            if any(pattern in h.lower() for h in mx_hosts):
                findings.append(ScanFinding(
                    domain=domain, severity="info", category="mx",
                    finding=f"SEG in MX path: {seg_name}",
                    detail=(
                        f"{seg_name} gateway detected in MX path. Mail forwarded through a SEG "
                        "re-sends from SEG infrastructure, which may fail SPF re-evaluation at "
                        "downstream receivers. Ensure DKIM signing is the primary DMARC "
                        "authentication method — it survives re-sending."
                    ),
                    source="_fingerprint_mx",
                ))

        return findings, None, tenant_mx, is_m365
    except Exception as exc:
        return findings, f"mx/{domain}: {exc}", tenant_mx, is_m365


# ── Tier 1 Entry Point ────────────────────────────────────────────────────────

def run_dns_scan(domains: list[str]) -> ScanReport:
    """Run Tier 1 passive DNS checks (SPF/DMARC/DKIM/MX) for all supplied domains."""
    report = ScanReport(domains=list(domains), generated_at=utc_now())

    for raw_domain in domains:
        domain = raw_domain.lower().strip()

        # MX first — is_m365 flag affects DKIM check
        mx_findings, mx_err, _tenant_mx, is_m365 = _fingerprint_mx(domain)
        report.findings.extend(mx_findings)
        if mx_err:
            report.errors.append(mx_err)

        for fn, label in (
            (_check_spf, "spf"),
            (_check_dmarc, "dmarc"),
        ):
            try:
                found, err = fn(domain)  # type: ignore[operator]
                report.findings.extend(found)
                if err:
                    report.errors.append(err)
            except Exception as exc:
                report.errors.append(f"{label}/{domain}: {exc}")

        dkim_findings, dkim_err = _check_dkim(domain, is_m365=is_m365)
        report.findings.extend(dkim_findings)
        if dkim_err:
            report.errors.append(dkim_err)

    return report


# ─────────────────────────────────────────────────────────────────────────────
# Tier 2 — SMTP Probing
# ─────────────────────────────────────────────────────────────────────────────

def _smtp_connect(host: str, port: int = 25, timeout: int = 10) -> socket.socket:
    return socket.create_connection((host, port), timeout=timeout)


def _smtp_readline(sock: socket.socket) -> str:
    data = b""
    while True:
        byte = sock.recv(1)
        if not byte:
            break
        data += byte
        if byte == b"\n":
            break
    return data.decode("ascii", errors="replace")


def _smtp_read_response(sock: socket.socket) -> tuple[int, str]:
    """Read a (possibly multi-line) SMTP response. Returns (code, full_text)."""
    lines: list[str] = []
    while True:
        line = _smtp_readline(sock)
        lines.append(line.rstrip("\r\n"))
        # Continuation line has '-' at position 3; final line has ' '
        if len(line) < 4 or line[3] != "-":
            break
    code_str = lines[0][:3] if lines else "000"
    try:
        code = int(code_str)
    except ValueError:
        code = 0
    return code, "\r\n".join(lines)


def _smtp_send(sock: socket.socket, command: str) -> tuple[int, str]:
    sock.sendall((command + "\r\n").encode("ascii", errors="replace"))
    return _smtp_read_response(sock)


def _run_smtp_probe(
    tenant_mx: str,
    test_recipient: str,
    spoofed_from: str,
    port: int = 25,
    timeout: int = 15,
) -> tuple[list[ScanFinding], str | None]:
    """
    Executes Tier 2 SMTP probes. Performs RSET/QUIT cleanly.
    Does NOT proceed to DATA or send any message body.
    """
    findings: list[ScanFinding] = []
    transcript: list[str] = []
    domain = spoofed_from.split("@")[-1] if "@" in spoofed_from else tenant_mx

    def log(direction: str, text: str) -> None:
        transcript.append(f"{direction} {text.strip()}")

    try:
        sock = _smtp_connect(tenant_mx, port=port, timeout=timeout)
    except Exception as exc:
        return findings, f"smtp_connect/{tenant_mx}:{port}: {exc}"

    try:
        # Banner
        code, banner = _smtp_read_response(sock)
        log("S:", banner)
        if code != 220:
            return findings, f"smtp/{tenant_mx}: unexpected banner ({code}): {banner[:120]}"

        # EHLO
        code, ehlo_resp = _smtp_send(sock, "EHLO cirrus-scan.local")
        log("C:", "EHLO cirrus-scan.local")
        log("S:", ehlo_resp)

        # STARTTLS check
        if "STARTTLS" in ehlo_resp.upper():
            findings.append(ScanFinding(
                domain=domain, severity="info", category="smtp",
                finding=f"STARTTLS offered by {tenant_mx}",
                detail=f"{tenant_mx} advertises STARTTLS. TLS is available for inbound mail connections.",
                source="_run_smtp_probe",
            ))
        else:
            findings.append(ScanFinding(
                domain=domain, severity="medium", category="smtp",
                finding=f"STARTTLS not offered by {tenant_mx}",
                detail=(
                    f"{tenant_mx} does not advertise STARTTLS in EHLO response. "
                    "Inbound SMTP connections can be made in cleartext."
                ),
                remediation=(
                    "Verify the MX endpoint is correctly configured. M365 EOP always offers "
                    "STARTTLS — absence may indicate a mis-configured connector or gateway."
                ),
                source="_run_smtp_probe",
            ))

        # ── Probe 1: Direct Send (spoofed internal domain MAIL FROM) ─────────
        code_mf, resp_mf = _smtp_send(sock, f"MAIL FROM:<{spoofed_from}>")
        log("C:", f"MAIL FROM:<{spoofed_from}>")
        log("S:", resp_mf)

        if code_mf == 250:
            # MAIL FROM accepted — probe RCPT TO for completeness
            code_rcpt, resp_rcpt = _smtp_send(sock, f"RCPT TO:<{test_recipient}>")
            log("C:", f"RCPT TO:<{test_recipient}>")
            log("S:", resp_rcpt)
            raw_transcript = "\n".join(transcript)
            findings.append(ScanFinding(
                domain=domain, severity="critical", category="smtp",
                finding=f"RejectDirectSend NOT enabled — {tenant_mx} accepted spoofed MAIL FROM",
                detail=(
                    f"MAIL FROM:<{spoofed_from}> accepted (250) by {tenant_mx}. "
                    f"Any device can relay mail claiming to originate from internal addresses "
                    f"without authentication. RCPT TO:<{test_recipient}>: {code_rcpt} — "
                    f"{resp_rcpt[:80]}. No message body was sent. Raw transcript below."
                ),
                remediation=(
                    "Enable RejectDirectSend in Exchange Online PowerShell:\n"
                    "  Set-OrganizationConfig -RejectDirectSend $true\n\n"
                    "This prevents unauthenticated senders from using the tenant MX endpoint "
                    "to send mail as internal domain addresses. Devices that legitimately need "
                    "to send mail should use authenticated SMTP (port 587) or the SMTP relay "
                    "connector with a static IP restriction."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/fix-issues-with-printers-scanners-and-lob-applications-that-send-email-using-microsoft-365-or-office-365",
                    "https://learn.microsoft.com/en-us/powershell/module/exchange/set-organizationconfig",
                ],
                source="_run_smtp_probe",
            ))
            findings.append(ScanFinding(
                domain=domain, severity="info", category="smtp",
                finding="SMTP transcript — direct send probe (evidence)",
                detail=raw_transcript,
                source="_run_smtp_probe",
            ))
            _smtp_send(sock, "RSET")
            log("C:", "RSET")

        elif code_mf in (550, 554, 530, 501, 503):
            findings.append(ScanFinding(
                domain=domain, severity="info", category="smtp",
                finding=f"RejectDirectSend active — spoofed MAIL FROM rejected ({code_mf})",
                detail=(
                    f"MAIL FROM:<{spoofed_from}> rejected by {tenant_mx} "
                    f"({code_mf}): {resp_mf[:150]}. Direct send is restricted."
                ),
                source="_run_smtp_probe",
            ))
        else:
            findings.append(ScanFinding(
                domain=domain, severity="high", category="smtp",
                finding=f"RejectDirectSend: unexpected response to spoofed MAIL FROM ({code_mf})",
                detail=(
                    f"MAIL FROM:<{spoofed_from}> returned an unexpected code {code_mf}: "
                    f"{resp_mf[:200]}. Manual review required to determine enforcement status."
                ),
                remediation=(
                    "Review the SMTP response against expected behavior. Consider explicitly "
                    "enabling RejectDirectSend: Set-OrganizationConfig -RejectDirectSend $true"
                ),
                source="_run_smtp_probe",
            ))

        # ── Probe 2: Null Sender (NDR/bounce spoofing) ────────────────────────
        code_null, resp_null = _smtp_send(sock, "MAIL FROM:<>")
        log("C:", "MAIL FROM:<>")
        log("S:", resp_null)

        if code_null == 250:
            code_rcpt_null, resp_rcpt_null = _smtp_send(sock, f"RCPT TO:<{test_recipient}>")
            log("C:", f"RCPT TO:<{test_recipient}>")
            log("S:", resp_rcpt_null)
            if code_rcpt_null == 250:
                findings.append(ScanFinding(
                    domain=domain, severity="high", category="smtp",
                    finding="Null sender (MAIL FROM:<>) accepted to internal recipient",
                    detail=(
                        f"MAIL FROM:<> (null sender / DSN bounce) accepted and "
                        f"RCPT TO:<{test_recipient}> also accepted ({code_rcpt_null}). "
                        "This enables NDR/bounce spoofing: an attacker can send apparent "
                        "non-delivery reports to internal mailboxes without authentication."
                    ),
                    remediation=(
                        "Review inbound connector configuration. Add a transport rule to block "
                        "or quarantine inbound MAIL FROM:<> messages from external IPs unless "
                        "the source is a known NDR relay. "
                        "Example: New-TransportRule -Name 'Block external null sender' "
                        "-FromScope NotInOrganization -HeaderMatchesMessageHeader 'Return-Path' "
                        "-HeaderMatchesPatterns '^<>$' -SetScl 9"
                    ),
                    source="_run_smtp_probe",
                ))
            else:
                findings.append(ScanFinding(
                    domain=domain, severity="info", category="smtp",
                    finding="Null sender accepted at MAIL FROM but RCPT TO rejected",
                    detail=(
                        f"MAIL FROM:<> accepted ({code_null}) but RCPT TO:<{test_recipient}> "
                        f"rejected ({code_rcpt_null}): {resp_rcpt_null[:80]}. "
                        "Delivery is blocked at recipient stage."
                    ),
                    source="_run_smtp_probe",
                ))
            _smtp_send(sock, "RSET")
            log("C:", "RSET")
        else:
            findings.append(ScanFinding(
                domain=domain, severity="info", category="smtp",
                finding="Null sender (MAIL FROM:<>) rejected at MAIL FROM",
                detail=f"MAIL FROM:<> rejected ({code_null}): {resp_null[:80]}.",
                source="_run_smtp_probe",
            ))

        _smtp_send(sock, "QUIT")
        log("C:", "QUIT")

        return findings, None

    except Exception as exc:
        return findings, f"smtp_probe/{tenant_mx}: {exc}"
    finally:
        try:
            sock.close()
        except Exception:
            pass


def run_smtp_scan(
    tenant_mx: str,
    test_recipient: str,
    spoofed_from: str,
    port: int = 25,
    timeout: int = 15,
    confirmed: bool = False,
) -> ScanReport:
    """
    Run Tier 2 SMTP probes against tenant_mx.

    confirmed must be True to proceed — callers must obtain explicit written
    authorization from the domain/tenant owner before setting this flag.
    """
    domain = spoofed_from.split("@")[-1] if "@" in spoofed_from else tenant_mx
    report = ScanReport(domains=[domain], generated_at=utc_now())

    if not confirmed:
        report.errors.append(
            "Authorization check failed: confirmed=False. "
            "Tier 2 SMTP probing makes TCP connections to the target MX on port 25. "
            "Pass --confirm after verifying written authorization from the domain owner."
        )
        return report

    findings, error = _run_smtp_probe(tenant_mx, test_recipient, spoofed_from, port=port, timeout=timeout)
    report.findings.extend(findings)
    if error:
        report.errors.append(error)

    return report


# ─────────────────────────────────────────────────────────────────────────────
# Tier 3 — Authenticated Tenant Audit (Exchange Online PowerShell)
# ─────────────────────────────────────────────────────────────────────────────

# PowerShell script that checks for an existing Exchange Online connection,
# then runs all audit cmdlets and returns JSON. Does NOT call
# Connect-ExchangeOnline — the operator must already be connected.
_SCAN_TENANT_SCRIPT = r"""
$ErrorActionPreference = 'Continue'
try {
    Import-Module ExchangeOnlineManagement -ErrorAction Stop
} catch {
    @{ __error = "ExchangeOnlineManagement module not found. Run: Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force" } | ConvertTo-Json -Compress
    exit 1
}

# Verify an active EXO session exists (EXO module v3+)
$conn = $null
try { $conn = Get-ConnectionInformation -ErrorAction SilentlyContinue } catch {}
if (-not $conn) {
    @{ __error = "Not connected to Exchange Online. Run Connect-ExchangeOnline before invoking cirrus scan tenant." } | ConvertTo-Json -Compress
    exit 1
}

$result = [ordered]@{}

try { $result.org_config = (Get-OrganizationConfig | Select-Object RejectDirectSend, OAuth2ClientProfileEnabled) } catch { $result.org_config = @{ __error = $_.Exception.Message } }

try { $result.dkim_signing = @(Get-DkimSigningConfig | Select-Object Domain,Enabled,Status,KeySize,Selector1CNAME,Selector2CNAME) } catch { $result.dkim_signing = @() }

try {
    $result.anti_phish = @(Get-AntiPhishPolicy | Select-Object
        Name,HonorDmarcPolicy,EnableSpoofIntelligence,EnableUnauthenticatedSender,
        EnableViaTag,AuthenticationFailAction,DmarcRejectAction,DmarcQuarantineAction)
} catch { $result.anti_phish = @() }

try {
    $result.content_filter = @(Get-HostedContentFilterPolicy | Select-Object
        Name,AllowedSenderDomains,AllowedSenders)
} catch { $result.content_filter = @() }

try {
    $result.transport_rules = @(Get-TransportRule | Select-Object
        Name,State,SetScl,SenderDomainIs,FromScope,SentToScope)
} catch { $result.transport_rules = @() }

try {
    $result.inbound_connectors = @(Get-InboundConnector | Select-Object
        Name,Enabled,ConnectorType,TreatMessagesAsInternal,SenderIPAddresses,SenderDomains)
} catch { $result.inbound_connectors = @() }

try {
    $result.accepted_domains = @(Get-AcceptedDomain | Select-Object DomainName,DomainType,Default)
} catch { $result.accepted_domains = @() }

$result | ConvertTo-Json -Depth 6 -Compress
"""


def _run_tenant_ps() -> tuple[dict[str, Any], str | None]:
    """Spawn PowerShell, run _SCAN_TENANT_SCRIPT, return parsed JSON dict or error."""
    from cirrus.utils.exchange_ps import find_powershell, check_exa_module_installed

    ps_path = find_powershell()
    if not ps_path:
        return {}, (
            "PowerShell not found. Install PowerShell 7: https://aka.ms/install-powershell"
        )

    is_installed, _ = check_exa_module_installed(ps_path)
    if not is_installed:
        return {}, (
            "ExchangeOnlineManagement module not installed. Run: cirrus deps install"
        )

    try:
        proc = subprocess.run(
            [ps_path, "-NoProfile", "-Command", _SCAN_TENANT_SCRIPT],
            capture_output=True,
            text=True,
            timeout=120,
            env=os.environ.copy(),
        )
    except subprocess.TimeoutExpired:
        return {}, "Exchange Online PowerShell timed out (2 min)."
    except Exception as exc:
        return {}, f"Failed to launch PowerShell: {exc}"

    stdout = proc.stdout.strip()
    if not stdout:
        stderr_snippet = proc.stderr.strip()[:300] if proc.stderr else "(no stderr)"
        return {}, f"PowerShell produced no output. stderr: {stderr_snippet}"

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return {}, f"PowerShell output is not valid JSON: {stdout[:300]}"

    if err := data.get("__error"):
        return {}, str(err)

    return data, None


def _analyze_org_config(domain: str, oc: dict) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    val = oc.get("RejectDirectSend")
    if str(val).lower() in ("false", "0", "no", ""):
        findings.append(ScanFinding(
            domain=domain, severity="critical", category="tenant",
            finding="RejectDirectSend=$false — unauthenticated direct send is open",
            detail=(
                f"Get-OrganizationConfig RejectDirectSend: {val}. Any device or application "
                "can send mail as any address in the tenant by connecting directly to the MX "
                "endpoint on port 25 without authentication."
            ),
            remediation="Set-OrganizationConfig -RejectDirectSend $true",
            references=[
                "https://learn.microsoft.com/en-us/powershell/module/exchange/set-organizationconfig"
            ],
            source="_analyze_org_config",
        ))
    else:
        findings.append(ScanFinding(
            domain=domain, severity="info", category="tenant",
            finding="RejectDirectSend=$true — direct send restricted",
            detail="Unauthenticated SMTP to the tenant MX is blocked for internal domain senders.",
            source="_analyze_org_config",
        ))
    return findings


def _analyze_dkim_signing(domain: str, configs: list[dict]) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    for cfg in configs:
        d = cfg.get("Domain", "") or domain
        enabled = str(cfg.get("Enabled", "")).lower() == "true"
        status = cfg.get("Status", "")
        try:
            key_size = int(cfg.get("KeySize") or 0)
        except (ValueError, TypeError):
            key_size = 0

        if not enabled:
            findings.append(ScanFinding(
                domain=d, severity="high", category="tenant",
                finding=f"DKIM signing disabled: {d}",
                detail=(
                    f"Get-DkimSigningConfig for '{d}': Enabled=False. Outbound mail from {d} "
                    "is not DKIM-signed, breaking DMARC DKIM alignment."
                ),
                remediation=f"Enable-DkimSigningConfig -Identity {d}",
                references=[
                    "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/use-dkim-to-validate-outbound-email"
                ],
                source="_analyze_dkim_signing",
            ))
        elif status and status.lower() not in ("valid", ""):
            findings.append(ScanFinding(
                domain=d, severity="high", category="tenant",
                finding=f"DKIM signing status not Valid: {d} — {status}",
                detail=(
                    f"Get-DkimSigningConfig '{d}': Enabled=True, Status={status}. "
                    "DKIM key may be unpublished or CNAME records may be missing from DNS."
                ),
                remediation=(
                    f"Check DNS CNAME records for selector1._domainkey.{d} and "
                    f"selector2._domainkey.{d}. Run: "
                    f"Get-DkimSigningConfig -Identity {d} | Select Selector1CNAME,Selector2CNAME"
                ),
                source="_analyze_dkim_signing",
            ))
        else:
            findings.append(ScanFinding(
                domain=d, severity="info", category="tenant",
                finding=f"DKIM signing active: {d}",
                detail=f"Enabled=True, Status={status or 'Valid'}, KeySize={key_size or 'unknown'}.",
                source="_analyze_dkim_signing",
            ))

        if key_size and key_size < 2048:
            findings.append(ScanFinding(
                domain=d, severity="medium", category="tenant",
                finding=f"DKIM key size weak: {d} ({key_size}-bit)",
                detail=f"DKIM signing key for '{d}' is {key_size} bits. Keys below 2048 bits are considered weak.",
                remediation=f"Rotate-DkimSigningConfig -KeySize 2048 -Identity {d}",
                source="_analyze_dkim_signing",
            ))
    return findings


def _analyze_anti_phish(domain: str, policies: list[dict]) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    for policy in policies:
        name = policy.get("Name", "unknown")

        def _bool(key: str, default: str = "true") -> bool:
            return str(policy.get(key, default)).lower() == "true"

        if not _bool("HonorDmarcPolicy"):
            findings.append(ScanFinding(
                domain=domain, severity="high", category="tenant",
                finding=f"Anti-phish '{name}': HonorDmarcPolicy=$false",
                detail=(
                    f"Policy '{name}' does not honor the domain's DMARC policy. "
                    "EOP compauth decisions can override p=reject, allowing spoofed mail "
                    "through DMARC enforcement."
                ),
                remediation=f"Set-AntiPhishPolicy -Identity '{name}' -HonorDmarcPolicy $true",
                references=[
                    "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-phishing-policies-about"
                ],
                source="_analyze_anti_phish",
            ))

        if not _bool("EnableSpoofIntelligence"):
            findings.append(ScanFinding(
                domain=domain, severity="critical", category="tenant",
                finding=f"Anti-phish '{name}': SpoofIntelligence disabled",
                detail=(
                    f"Policy '{name}' has EnableSpoofIntelligence=$false. "
                    "Anti-spoofing intelligence is completely disabled — spoofed senders "
                    "bypass detection entirely."
                ),
                remediation=f"Set-AntiPhishPolicy -Identity '{name}' -EnableSpoofIntelligence $true",
                references=[
                    "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-phishing-policies-about"
                ],
                source="_analyze_anti_phish",
            ))

        if not _bool("EnableUnauthenticatedSender"):
            findings.append(ScanFinding(
                domain=domain, severity="medium", category="tenant",
                finding=f"Anti-phish '{name}': UnauthenticatedSender indicator disabled",
                detail=(
                    f"Policy '{name}' has EnableUnauthenticatedSender=$false. "
                    "The '?' question-mark indicator on unauthenticated senders in Outlook is suppressed."
                ),
                remediation=f"Set-AntiPhishPolicy -Identity '{name}' -EnableUnauthenticatedSender $true",
                source="_analyze_anti_phish",
            ))

        auth_fail = str(policy.get("AuthenticationFailAction", "")).lower()
        if auth_fail == "movetojmf":
            findings.append(ScanFinding(
                domain=domain, severity="medium", category="tenant",
                finding=f"Anti-phish '{name}': AuthenticationFailAction=MoveToJmf",
                detail=(
                    f"Policy '{name}' moves unauthenticated mail to Junk rather than Quarantine. "
                    "Junk is end-user accessible and less visible to security teams."
                ),
                remediation=f"Set-AntiPhishPolicy -Identity '{name}' -AuthenticationFailAction Quarantine",
                source="_analyze_anti_phish",
            ))

        dmarc_action = str(policy.get("DmarcRejectAction", "")).lower()
        if dmarc_action not in ("quarantine", "reject"):
            findings.append(ScanFinding(
                domain=domain, severity="high", category="tenant",
                finding=f"Anti-phish '{name}': DmarcRejectAction not Quarantine/Reject",
                detail=(
                    f"Policy '{name}' DmarcRejectAction={dmarc_action or 'not set'}. "
                    "Mail failing DMARC p=reject may not be rejected or quarantined by EOP."
                ),
                remediation=(
                    f"Set-AntiPhishPolicy -Identity '{name}' "
                    "-DmarcRejectAction Reject -DmarcQuarantineAction Quarantine"
                ),
                references=[
                    "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-phishing-policies-about"
                ],
                source="_analyze_anti_phish",
            ))

    return findings


def _analyze_content_filter(
    domain: str, policies: list[dict], accepted_domains: set[str]
) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    for policy in policies:
        name = policy.get("Name", "unknown")
        raw = policy.get("AllowedSenderDomains") or []
        if isinstance(raw, str):
            allowed = [x.strip() for x in raw.split(";") if x.strip()]
        elif isinstance(raw, list):
            # PS may return list of objects with Domain property
            allowed = []
            for item in raw:
                if isinstance(item, dict):
                    allowed.append(str(item.get("Domain", item)).strip())
                else:
                    allowed.append(str(item).strip())
        else:
            allowed = []

        for d in allowed:
            if d.lower() in accepted_domains:
                findings.append(ScanFinding(
                    domain=domain, severity="critical", category="tenant",
                    finding=f"Internal domain '{d}' in AllowedSenderDomains (policy: {name})",
                    detail=(
                        f"Policy '{name}' lists accepted domain '{d}' in AllowedSenderDomains. "
                        "Any mail claiming to be from {d} completely bypasses SPF, DKIM, and "
                        "DMARC evaluation — this is a total authentication bypass."
                    ),
                    remediation=(
                        f"Remove '{d}' from AllowedSenderDomains on policy '{name}'. "
                        "Internal domains must never appear in allow lists. "
                        "Set-HostedContentFilterPolicy -Identity '{name}' -AllowedSenderDomains "
                        "(rebuild list without {d})."
                    ),
                    source="_analyze_content_filter",
                ))
            else:
                findings.append(ScanFinding(
                    domain=domain, severity="info", category="tenant",
                    finding=f"External domain allowed (bypass): {d} (policy: {name})",
                    detail=(
                        f"Policy '{name}' bypasses spam filtering for mail from '{d}'. "
                        "Verify this is intentional and the domain is trusted."
                    ),
                    source="_analyze_content_filter",
                ))
    return findings


def _analyze_transport_rules(
    domain: str, rules: list[dict], accepted_domains: set[str]
) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    for rule in rules:
        name = rule.get("Name", "unknown")
        state = str(rule.get("State", "")).lower()
        set_scl = rule.get("SetScl")
        raw_sdi = rule.get("SenderDomainIs") or []
        from_scope = str(rule.get("FromScope", "")).lower()

        if isinstance(raw_sdi, str):
            sender_domains = [x.strip() for x in raw_sdi.split(";") if x.strip()]
        elif isinstance(raw_sdi, list):
            sender_domains = [str(x).strip() for x in raw_sdi if x]
        else:
            sender_domains = []

        scl_val: int | None = None
        if set_scl is not None:
            try:
                scl_val = int(set_scl)
            except (ValueError, TypeError):
                pass

        if scl_val == -1:
            internal_sdi = [d for d in sender_domains if d.lower() in accepted_domains]
            external_scope = from_scope not in ("inorganization", "internal")

            if internal_sdi and external_scope:
                findings.append(ScanFinding(
                    domain=domain, severity="critical", category="tenant",
                    finding=f"Transport rule '{name}': SCL=-1 bypass for mail claiming internal domain",
                    detail=(
                        f"Rule '{name}' (State: {state}) sets SCL=-1 (spam bypass) when "
                        f"SenderDomainIs matches: {', '.join(internal_sdi)}. FromScope is not "
                        f"restricted to InOrganization ({from_scope or 'not set'}). External "
                        "senders spoofing these domains bypass all spam filtering."
                    ),
                    remediation=(
                        f"Restrict rule '{name}' to InOrganization scope, or add a condition "
                        "that verifies the X-MS-Exchange-CrossTenant-Id header matches your "
                        "tenant ID to ensure the message originated from within your tenant."
                    ),
                    source="_analyze_transport_rules",
                ))
            else:
                findings.append(ScanFinding(
                    domain=domain, severity="high", category="tenant",
                    finding=f"Transport rule '{name}': SetScl=-1 (spam bypass) — review scope",
                    detail=(
                        f"Rule '{name}' (State: {state}) sets SCL=-1. "
                        f"SenderDomains: {', '.join(sender_domains) or 'any'}. "
                        f"FromScope: {from_scope or 'not set'}."
                    ),
                    remediation=(
                        f"Review rule '{name}' to confirm it cannot be triggered by external "
                        "senders. Add tenant ID header verification if scope is not restricted."
                    ),
                    source="_analyze_transport_rules",
                ))
        elif sender_domains:
            internal_sdi = [d for d in sender_domains if d.lower() in accepted_domains]
            external_scope = from_scope not in ("inorganization", "internal")
            if internal_sdi and external_scope:
                findings.append(ScanFinding(
                    domain=domain, severity="high", category="tenant",
                    finding=f"Transport rule '{name}': trusts mail claiming internal domain without scope restriction",
                    detail=(
                        f"Rule '{name}' (State: {state}) has SenderDomainIs matching accepted "
                        f"domains ({', '.join(internal_sdi)}) without restricting FromScope to "
                        f"InOrganization ({from_scope or 'not set'}). External spoofed senders "
                        "may trigger this rule's actions."
                    ),
                    remediation=(
                        f"Add FromScope=InOrganization condition to rule '{name}', or add a "
                        "HeaderMatchesMessageHeader condition on X-MS-Exchange-CrossTenant-Id "
                        "to confirm the message is genuinely internal."
                    ),
                    source="_analyze_transport_rules",
                ))
    return findings


def _analyze_inbound_connectors(domain: str, connectors: list[dict]) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    for conn in connectors:
        name = conn.get("Name", "unknown")
        enabled = str(conn.get("Enabled", "true")).lower() == "true"
        if not enabled:
            continue

        treat_internal = str(conn.get("TreatMessagesAsInternal", "false")).lower() == "true"
        raw_ips = conn.get("SenderIPAddresses") or []
        conn_type = str(conn.get("ConnectorType", "")).lower()

        if isinstance(raw_ips, str):
            sender_ips = [x.strip() for x in raw_ips.split(";") if x.strip()]
        elif isinstance(raw_ips, list):
            sender_ips = [str(x).strip() for x in raw_ips if x]
        else:
            sender_ips = []

        if treat_internal:
            findings.append(ScanFinding(
                domain=domain, severity="critical", category="tenant",
                finding=f"Inbound connector '{name}': TreatMessagesAsInternal=$true",
                detail=(
                    f"Connector '{name}' marks all mail passing through it as internal. "
                    "External sender safeguards, anti-spoofing checks, and EOP filtering are "
                    "bypassed entirely for mail received on this connector."
                ),
                remediation=(
                    f"Set-InboundConnector -Identity '{name}' -TreatMessagesAsInternal $false "
                    "unless this connector exclusively handles authenticated relay from a "
                    "verified on-premises system with a tightly restricted SenderIPAddresses list."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/use-connectors-to-configure-mail-flow/set-up-connectors-to-route-mail"
                ],
                source="_analyze_inbound_connectors",
            ))

        if not sender_ips:
            findings.append(ScanFinding(
                domain=domain, severity="high", category="tenant",
                finding=f"Inbound connector '{name}': no SenderIPAddresses restriction",
                detail=(
                    f"Connector '{name}' (Type: {conn_type}) has no IP address restriction. "
                    "Any source IP can trigger this connector's trust or policy settings."
                ),
                remediation=(
                    f"Set-InboundConnector -Identity '{name}' "
                    "-SenderIPAddresses <specific-ip-range(s)>"
                ),
                source="_analyze_inbound_connectors",
            ))
        elif conn_type == "partner":
            findings.append(ScanFinding(
                domain=domain, severity="medium", category="tenant",
                finding=f"Inbound connector '{name}': Partner connector — verify IP scope",
                detail=(
                    f"Partner connector '{name}' restricts to IPs: "
                    f"{', '.join(sender_ips[:5])}{'...' if len(sender_ips) > 5 else ''}. "
                    "Verify these are narrow, current, and legitimately associated with the partner."
                ),
                source="_analyze_inbound_connectors",
            ))

    return findings


def _analyze_accepted_domains(
    domain: str, accepted: list[dict], dkim_enabled_domains: set[str]
) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    for acc in accepted:
        d = str(acc.get("DomainName", "")).lower()
        domain_type = acc.get("DomainType", "")
        is_default = str(acc.get("Default", "false")).lower() == "true"
        dkim_status = "enabled" if d in dkim_enabled_domains else "NOT enabled"

        findings.append(ScanFinding(
            domain=d, severity="info", category="tenant",
            finding=f"Accepted domain: {d} (Type: {domain_type}{', Default' if is_default else ''})",
            detail=f"Direct-send target for this tenant. DKIM signing: {dkim_status}.",
            source="_analyze_accepted_domains",
        ))

        if d not in dkim_enabled_domains:
            findings.append(ScanFinding(
                domain=d, severity="high", category="tenant",
                finding=f"Accepted domain '{d}' missing enabled DKIM signing config",
                detail=(
                    f"'{d}' is accepted by the tenant but DKIM signing is disabled or not "
                    "configured. Outbound mail from this domain will not be DKIM-signed."
                ),
                remediation=(
                    f"New-DkimSigningConfig -DomainName {d} -Enabled $true\n"
                    f"Or: Enable-DkimSigningConfig -Identity {d}"
                ),
                references=[
                    "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/use-dkim-to-validate-outbound-email"
                ],
                source="_analyze_accepted_domains",
            ))
    return findings


def run_tenant_scan(domain: str) -> ScanReport:
    """
    Run Tier 3 authenticated tenant audit.

    Requires an active Exchange Online PowerShell session in the calling
    process (Connect-ExchangeOnline already run by the operator).
    Does NOT attempt to establish a connection automatically.
    """
    report = ScanReport(domains=[domain], generated_at=utc_now())

    data, error = _run_tenant_ps()
    if error:
        report.errors.append(error)
        return report

    # Accepted domains used as reference set for several checks
    accepted_raw: list[dict] = data.get("accepted_domains") or []
    accepted_domains: set[str] = {str(a.get("DomainName", "")).lower() for a in accepted_raw}

    # DKIM enabled domains for cross-reference
    dkim_configs: list[dict] = data.get("dkim_signing") or []
    dkim_enabled: set[str] = {
        str(c.get("Domain", "")).lower()
        for c in dkim_configs
        if str(c.get("Enabled", "")).lower() == "true"
    }

    checks: list[tuple[str, list[ScanFinding]]] = [
        ("org_config",          _analyze_org_config(domain, data.get("org_config") or {})),
        ("dkim_signing",        _analyze_dkim_signing(domain, dkim_configs)),
        ("anti_phish",          _analyze_anti_phish(domain, data.get("anti_phish") or [])),
        ("content_filter",      _analyze_content_filter(domain, data.get("content_filter") or [], accepted_domains)),
        ("transport_rules",     _analyze_transport_rules(domain, data.get("transport_rules") or [], accepted_domains)),
        ("inbound_connectors",  _analyze_inbound_connectors(domain, data.get("inbound_connectors") or [])),
        ("accepted_domains",    _analyze_accepted_domains(domain, accepted_raw, dkim_enabled)),
    ]

    for _name, findings in checks:
        report.findings.extend(findings)

    return report


# ─────────────────────────────────────────────────────────────────────────────
# Combined run (all tiers)
# ─────────────────────────────────────────────────────────────────────────────

def run_full_scan(
    domains: list[str],
    tenant_mx: str | None = None,
    test_recipient: str | None = None,
    spoofed_from: str | None = None,
    smtp_confirmed: bool = False,
    run_tenant: bool = False,
    tenant_domain: str | None = None,
) -> ScanReport:
    """
    Run all requested scan tiers and merge findings into a single ScanReport.
    """
    all_domains = list(domains)
    if tenant_domain and tenant_domain not in all_domains:
        all_domains.append(tenant_domain)

    report = run_dns_scan(domains)

    if tenant_mx and test_recipient and spoofed_from:
        smtp_report = run_smtp_scan(
            tenant_mx=tenant_mx,
            test_recipient=test_recipient,
            spoofed_from=spoofed_from,
            confirmed=smtp_confirmed,
        )
        report.findings.extend(smtp_report.findings)
        report.errors.extend(smtp_report.errors)

    if run_tenant and tenant_domain:
        tenant_report = run_tenant_scan(tenant_domain)
        report.findings.extend(tenant_report.findings)
        report.errors.extend(tenant_report.errors)
        for d in tenant_report.domains:
            if d not in report.domains:
                report.domains.append(d)

    return report
