"""
DNS-based compliance checks.

Queries public DNS records to verify email authentication configuration:
  - DMARC  (_dmarc.<domain>       TXT)
  - SPF    (<domain>              TXT, v=spf1)
  - DKIM   (selector1/2._domainkey.<domain>  CNAME or TXT)

No credentials or API access required — all records are public DNS.
Requires: dnspython
"""

from __future__ import annotations

from dataclasses import dataclass, field

try:
    import dns.exception
    import dns.rdatatype
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class DmarcResult:
    found: bool
    record: str = ""
    policy: str = ""          # none | quarantine | reject
    subdomain_policy: str = ""
    pct: int = 100
    has_rua: bool = False      # aggregate report address configured

    @property
    def is_compliant(self) -> bool:
        return self.found and self.policy in ("quarantine", "reject")

    @property
    def status_detail(self) -> str:
        if not self.found:
            return "No DMARC record found"
        if not self.policy:
            return "DMARC record found but no p= policy tag"
        return f"p={self.policy}" + (f" pct={self.pct}" if self.pct != 100 else "")


@dataclass
class SpfResult:
    found: bool
    record: str = ""
    mechanism: str = ""        # -all | ~all | +all | ?all
    includes_o365: bool = False

    @property
    def is_compliant(self) -> bool:
        return self.found and self.mechanism in ("-all", "~all")

    @property
    def status_detail(self) -> str:
        if not self.found:
            return "No SPF record found"
        return f"SPF found ({self.mechanism or 'no -all/~all'})"


@dataclass
class DkimResult:
    selector1_found: bool = False
    selector2_found: bool = False
    selector1_record: str = ""
    selector2_record: str = ""

    @property
    def is_compliant(self) -> bool:
        return self.selector1_found or self.selector2_found

    @property
    def status_detail(self) -> str:
        found = []
        if self.selector1_found:
            found.append("selector1")
        if self.selector2_found:
            found.append("selector2")
        return f"DKIM selectors found: {', '.join(found)}" if found else "No DKIM selectors found"


@dataclass
class DomainDnsResults:
    domain: str
    dmarc: DmarcResult = field(default_factory=lambda: DmarcResult(found=False))
    spf: SpfResult = field(default_factory=lambda: SpfResult(found=False))
    dkim: DkimResult = field(default_factory=DkimResult)
    error: str = ""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _resolve_txt(name: str) -> list[str]:
    """Return all TXT record strings for a DNS name."""
    if not DNS_AVAILABLE:
        return []
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=10)
        results = []
        for rdata in answers:
            txt = "".join(
                part.decode("utf-8", errors="replace") if isinstance(part, bytes) else part
                for part in rdata.strings
            )
            results.append(txt)
        return results
    except Exception:
        return []


def _resolve_cname(name: str) -> str:
    """Return the CNAME target for a DNS name, or empty string."""
    if not DNS_AVAILABLE:
        return ""
    try:
        answers = dns.resolver.resolve(name, "CNAME", lifetime=10)
        return str(answers[0].target)
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Public check functions
# ---------------------------------------------------------------------------

def check_dmarc(domain: str) -> DmarcResult:
    """Check for a valid DMARC record at _dmarc.<domain>."""
    records = _resolve_txt(f"_dmarc.{domain}")
    dmarc_records = [r for r in records if r.strip().startswith("v=DMARC1")]

    if not dmarc_records:
        return DmarcResult(found=False)

    record = dmarc_records[0]
    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip().lower()] = v.strip()

    return DmarcResult(
        found=True,
        record=record,
        policy=tags.get("p", "").lower(),
        subdomain_policy=tags.get("sp", "").lower(),
        pct=int(tags["pct"]) if "pct" in tags and tags["pct"].isdigit() else 100,
        has_rua="rua" in tags,
    )


def check_spf(domain: str) -> SpfResult:
    """Check for a valid SPF record at <domain>."""
    records = _resolve_txt(domain)
    spf_records = [r for r in records if r.strip().startswith("v=spf1")]

    if not spf_records:
        return SpfResult(found=False)

    record = spf_records[0]
    mechanism = ""
    for qualifier in ("-all", "~all", "+all", "?all"):
        if qualifier in record:
            mechanism = qualifier
            break

    includes_o365 = "spf.protection.outlook.com" in record

    return SpfResult(
        found=True,
        record=record,
        mechanism=mechanism,
        includes_o365=includes_o365,
    )


def check_dkim(domain: str) -> DkimResult:
    """
    Check for DKIM selectors at selector1/selector2._domainkey.<domain>.

    M365 publishes CNAME records for DKIM selectors pointing to
    protection.outlook.com. A custom DKIM setup may use TXT records instead.
    """
    result = DkimResult()

    for selector, attr_found, attr_record in (
        ("selector1", "selector1_found", "selector1_record"),
        ("selector2", "selector2_found", "selector2_record"),
    ):
        name = f"{selector}._domainkey.{domain}"

        # Check CNAME (M365 default)
        cname = _resolve_cname(name)
        if cname:
            setattr(result, attr_found, True)
            setattr(result, attr_record, f"CNAME → {cname}")
            continue

        # Check TXT (custom DKIM or fallback)
        txts = _resolve_txt(name)
        dkim_txts = [t for t in txts if "v=DKIM1" in t or "k=rsa" in t]
        if dkim_txts:
            setattr(result, attr_found, True)
            setattr(result, attr_record, dkim_txts[0][:80])

    return result


def check_all_dns(domain: str) -> DomainDnsResults:
    """Run all DNS checks for a single domain."""
    if not DNS_AVAILABLE:
        return DomainDnsResults(domain=domain, error="dnspython not installed")
    try:
        return DomainDnsResults(
            domain=domain,
            dmarc=check_dmarc(domain),
            spf=check_spf(domain),
            dkim=check_dkim(domain),
        )
    except Exception as e:
        return DomainDnsResults(domain=domain, error=str(e))
