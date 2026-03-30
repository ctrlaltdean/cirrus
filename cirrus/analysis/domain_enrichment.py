"""
Domain Enrichment Module

Enriches domain names extracted from case collector output with:

  RDAP registration age  — How old is the domain? Newly registered domains
    (< 30 days) on forwarding destinations or external email addresses are
    a strong BEC / phishing indicator. Uses the IANA RDAP bootstrap registry
    to find the authoritative RDAP server — no API key required.

  MX records  — What mail servers does the domain route to? Domains forwarding
    to free webmail (gmail.com, outlook.com, protonmail.com, etc.) or to
    no MX at all are suspicious in a BEC context.

  SPF / DMARC presence  — Does the domain publish email authentication records?
    A domain with no SPF or DMARC can be spoofed trivially. Particularly
    relevant when a forwarding destination has weak or absent controls.

Domains are extracted from:
  - FORWARDS_TO:<email>         flags in mailbox_rules.json / mail_forwarding.json
  - EXTERNAL_SMTP_FORWARD:<email>  flags in mail_forwarding.json
  - EXTERNAL_EMAIL_OTP:<domain> flags in mfa_methods.json

Output is written to domain_enrichment.json in the case directory.
Run via `cirrus enrich-domains <case_dir>`.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import requests

# ── dnspython is a declared dependency ───────────────────────────────────────
try:
    import dns.resolver
    import dns.exception
    _DNS_AVAILABLE = True
except ImportError:
    _DNS_AVAILABLE = False

# ── Constants ─────────────────────────────────────────────────────────────────

# IANA RDAP bootstrap for TLD → authoritative RDAP base URL
_RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
_RDAP_THROTTLE = 0.5   # seconds between RDAP requests

# Free webmail / consumer mail providers — domain routing to these is suspicious
_CONSUMER_MAIL_DOMAINS: frozenset[str] = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "yahoo.com", "ymail.com", "protonmail.com", "proton.me", "tutanota.com",
    "tutanota.de", "icloud.com", "me.com", "mac.com", "aol.com",
    "zoho.com", "mail.com", "gmx.com", "gmx.net", "fastmail.com",
    "yandex.com", "yandex.ru",
})

# Domains new within this many days are considered suspicious
_NEW_DOMAIN_DAYS = 30


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class DomainEnrichment:
    domain: str
    registration_date: str = ""          # ISO-8601, from RDAP
    age_days: int | None = None          # days since registration; None = unknown
    registrar: str = ""
    mx_records: list[str] = field(default_factory=list)   # sorted MX hostnames
    routes_to_consumer_mail: bool = False
    has_spf: bool | None = None          # None = lookup failed
    has_dmarc: bool | None = None
    threat_summary: list[str] = field(default_factory=list)
    rdap_error: str = ""
    dns_error: str = ""


# ── Domain extraction ─────────────────────────────────────────────────────────

def _extract_domains_from_case(case_dir: Path) -> set[str]:
    """
    Walk all collector JSON files in the case directory and extract domain
    names from IOC flags that reference external email addresses or domains.
    """
    domains: set[str] = set()
    flag_prefixes = (
        "FORWARDS_TO:",
        "EXTERNAL_SMTP_FORWARD:",
        "EXTERNAL_EMAIL_OTP:",
        "FORWARDING_ADDRESS:",
    )

    for json_file in case_dir.glob("*.json"):
        try:
            records = json.loads(json_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError, IsADirectoryError):
            continue
        if not isinstance(records, list):
            continue
        for record in records:
            for flag in record.get("_iocFlags") or []:
                for prefix in flag_prefixes:
                    if flag.startswith(prefix):
                        value = flag[len(prefix):]
                        # value is email address or bare domain
                        if "@" in value:
                            domain = value.split("@")[-1].lower().strip()
                        else:
                            domain = value.lower().strip()
                        if domain and "." in domain:
                            domains.add(domain)

    return domains


# ── RDAP lookups ──────────────────────────────────────────────────────────────

def _load_rdap_bootstrap(session: requests.Session) -> dict[str, str]:
    """
    Fetch the IANA RDAP bootstrap list and build a TLD → base URL mapping.
    Returns empty dict on failure (we'll fall back to missing registration data).
    """
    try:
        resp = session.get(_RDAP_BOOTSTRAP_URL, timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return {}

    tld_map: dict[str, str] = {}
    for entry in data.get("services") or []:
        if len(entry) < 2:
            continue
        tlds, urls = entry[0], entry[1]
        base_url = urls[-1] if urls else ""
        for tld in tlds:
            tld_map[tld.lower()] = base_url
    return tld_map


def _rdap_lookup(session: requests.Session, domain: str, tld_map: dict[str, str]) -> dict:
    """
    Look up a domain via RDAP. Returns the parsed JSON dict or raises on error.
    """
    tld = domain.rsplit(".", 1)[-1].lower()
    base = tld_map.get(tld, "")
    if not base:
        raise ValueError(f"No RDAP server found for TLD .{tld}")
    url = f"{base.rstrip('/')}/domain/{domain}"
    resp = session.get(url, timeout=10)
    resp.raise_for_status()
    return resp.json()


def _parse_registration_date(rdap_data: dict) -> tuple[str, str]:
    """
    Extract registration date and registrar from RDAP response.
    Returns (iso_date_str, registrar_name).
    """
    reg_date = ""
    registrar = ""

    for event in rdap_data.get("events") or []:
        action = (event.get("eventAction") or "").lower()
        if action == "registration":
            reg_date = event.get("eventDate") or ""
            break

    for entity in rdap_data.get("entities") or []:
        roles = entity.get("roles") or []
        if "registrar" in roles:
            vcard = entity.get("vcardArray") or []
            if len(vcard) > 1:
                for item in vcard[1]:
                    if item and item[0] == "fn":
                        registrar = item[-1] or ""
                        break
            if not registrar:
                registrar = entity.get("handle") or ""
            break

    return reg_date, registrar


def _compute_age_days(reg_date: str) -> int | None:
    if not reg_date:
        return None
    try:
        dt = datetime.fromisoformat(reg_date.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except (ValueError, TypeError):
        return None


# ── DNS lookups ───────────────────────────────────────────────────────────────

def _mx_lookup(domain: str) -> list[str]:
    """Return sorted list of MX hostnames for the domain."""
    if not _DNS_AVAILABLE:
        return []
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        return sorted(str(r.exchange).rstrip(".").lower() for r in answers)
    except (dns.exception.DNSException, Exception):
        return []


def _txt_lookup(domain: str, prefix: str) -> bool | None:
    """
    Check for a TXT record with a given prefix (e.g. "v=spf1", "v=DMARC1").
    Returns True if found, False if definitely absent, None on lookup error.
    """
    if not _DNS_AVAILABLE:
        return None
    lookup_domain = domain if prefix.startswith("v=spf") else f"_dmarc.{domain}"
    try:
        answers = dns.resolver.resolve(lookup_domain, "TXT", lifetime=5)
        for r in answers:
            txt = "".join(s.decode("utf-8", errors="ignore") if isinstance(s, bytes) else s
                          for s in r.strings)
            if txt.lower().startswith(prefix.lower()):
                return True
        return False
    except dns.resolver.NXDOMAIN:
        return False
    except (dns.exception.DNSException, Exception):
        return None


# ── Enrichment runner ─────────────────────────────────────────────────────────

def enrich_domains(
    domains: set[str],
    on_progress: Callable[[str], None] | None = None,
) -> dict[str, DomainEnrichment]:
    """
    Enrich a set of domain names with RDAP registration data and DNS records.

    Args:
        domains:     Set of domain names to enrich.
        on_progress: Optional callback called with a status string per domain.

    Returns dict mapping domain -> DomainEnrichment.
    """
    session = requests.Session()
    session.headers.update({"Accept": "application/rdap+json, application/json"})

    tld_map = _load_rdap_bootstrap(session)
    results: dict[str, DomainEnrichment] = {}

    for domain in sorted(domains):
        if on_progress:
            on_progress(domain)

        enrichment = DomainEnrichment(domain=domain)

        # ── RDAP ──────────────────────────────────────────────────────────────
        try:
            rdap_data = _rdap_lookup(session, domain, tld_map)
            reg_date, registrar = _parse_registration_date(rdap_data)
            enrichment.registration_date = reg_date
            enrichment.registrar = registrar
            enrichment.age_days = _compute_age_days(reg_date)
        except Exception as exc:
            enrichment.rdap_error = str(exc)[:120]
        time.sleep(_RDAP_THROTTLE)

        # ── DNS: MX ───────────────────────────────────────────────────────────
        enrichment.mx_records = _mx_lookup(domain)
        if enrichment.mx_records:
            for mx in enrichment.mx_records:
                mx_root = ".".join(mx.rsplit(".", 2)[-2:]) if mx.count(".") >= 2 else mx
                if mx_root in _CONSUMER_MAIL_DOMAINS or mx in _CONSUMER_MAIL_DOMAINS:
                    enrichment.routes_to_consumer_mail = True
                    break

        # ── DNS: SPF / DMARC ──────────────────────────────────────────────────
        enrichment.has_spf   = _txt_lookup(domain, "v=spf1")
        enrichment.has_dmarc = _txt_lookup(domain, "v=DMARC1")

        # ── Threat summary ────────────────────────────────────────────────────
        tags: list[str] = []
        if enrichment.age_days is not None and enrichment.age_days < _NEW_DOMAIN_DAYS:
            tags.append(f"NEW_DOMAIN:{enrichment.age_days}d")
        if enrichment.routes_to_consumer_mail:
            tags.append("CONSUMER_MAIL_MX")
        if not enrichment.mx_records:
            tags.append("NO_MX")
        if enrichment.has_spf is False:
            tags.append("NO_SPF")
        if enrichment.has_dmarc is False:
            tags.append("NO_DMARC")
        enrichment.threat_summary = tags

        results[domain] = enrichment

    return results


def run_domain_enrichment(
    case_dir: Path,
    on_progress: Callable[[str], None] | None = None,
) -> dict:
    """
    Extract domains from a case directory, enrich them, and write
    domain_enrichment.json. Returns the summary dict.
    """
    domains = _extract_domains_from_case(case_dir)

    if not domains:
        result = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_domains": 0,
            "suspicious_count": 0,
            "domains": {},
        }
        out = case_dir / "domain_enrichment.json"
        out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        return result

    enriched = enrich_domains(domains, on_progress=on_progress)

    domains_dict = {d: asdict(e) for d, e in enriched.items()}
    suspicious_count = sum(1 for e in enriched.values() if e.threat_summary)

    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_domains": len(enriched),
        "suspicious_count": suspicious_count,
        "domains": domains_dict,
    }

    out = case_dir / "domain_enrichment.json"
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    return result
