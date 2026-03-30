"""
IP Enrichment Module

Enriches public IP addresses extracted from case collector output with
geolocation, ASN, and threat intelligence data. Two data sources are used:

  Primary   — ip-api.com (free, no key required)
              Batch endpoint: up to 100 IPs per POST, 15 batches/minute.
              Returns: country, city, ASN, org/ISP, is_datacenter, is_proxy, is_tor.

  Secondary — AbuseIPDB (optional, requires a free API key)
              Register at: https://www.abuseipdb.com/register
              API documentation: https://docs.abuseipdb.com/
              Free tier: 1,000 requests/day.
              Returns: abuse confidence score (0–100) and total abuse reports.

              Set your API key via the environment variable ABUSEIPDB_KEY:
                export ABUSEIPDB_KEY="your_key_here"
              If the variable is not set, AbuseIPDB enrichment is silently
              skipped and ip-api.com data is still collected.

Output is written to ip_enrichment.json in the case directory. This file is
keyed by IP address string and never mutates the collector output files.

The enrichment step is intentionally NOT run automatically during workflow
execution — it makes external network calls to third-party services and
analysts should opt in explicitly via `cirrus enrich`.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

import requests

from cirrus.utils.helpers import is_private_ip

# ── ip-api.com constants ──────────────────────────────────────────────────────
_IPAPI_BATCH_URL  = "http://ip-api.com/batch"
_IPAPI_BATCH_SIZE = 100     # max IPs per POST
_IPAPI_FIELDS     = (
    "query,status,message,country,countryCode,city,org,isp,as,"
    "proxy,hosting,tor"
)

# ── AbuseIPDB constants ───────────────────────────────────────────────────────
_ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
_ABUSEIPDB_MAX_AGE   = 90   # days to look back for reports
_ABUSEIPDB_THROTTLE  = 1.1  # seconds between requests (free tier: ~1 req/sec)


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class IPEnrichment:
    ip: str
    country_code: str = ""
    country_name: str = ""
    city: str = ""
    asn: str = ""
    org: str = ""
    isp: str = ""
    is_datacenter: bool = False
    is_proxy: bool = False
    is_tor: bool = False
    abuse_score: int | None = None      # 0–100; None = AbuseIPDB not queried
    abuse_reports: int | None = None    # None = AbuseIPDB not queried
    error: str = ""

    @property
    def threat_summary(self) -> list[str]:
        """Return a list of threat indicator strings for display."""
        tags: list[str] = []
        if self.is_tor:
            tags.append("TOR_EXIT_NODE")
        if self.is_datacenter:
            tags.append("DATACENTER/HOSTING")
        if self.is_proxy:
            tags.append("PROXY/VPN")
        if self.abuse_score is not None and self.abuse_score >= 25:
            tags.append(f"ABUSE_SCORE:{self.abuse_score}")
        return tags

    @property
    def is_suspicious(self) -> bool:
        """True when the IP has at least one threat indicator."""
        return bool(self.threat_summary)


# ── IP extraction ─────────────────────────────────────────────────────────────

def extract_ips_from_case(case_dir: Path) -> set[str]:
    """
    Scan all *.json files in the case directory for IP address fields.

    Looks for:
      - "ipAddress" keys in any object (sign-in logs, audit logs)
      - PUBLIC_IP:<ip> flags in "_iocFlags" lists

    Returns a deduplicated set of public IP strings.
    """
    ips: set[str] = set()

    for json_file in case_dir.glob("*.json"):
        if json_file.name in ("ip_enrichment.json", "ioc_correlation.json"):
            continue  # skip output files
        try:
            with json_file.open(encoding="utf-8") as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError):
            continue

        records = data if isinstance(data, list) else []
        for record in records:
            if not isinstance(record, dict):
                continue

            # Direct ipAddress field
            ip = record.get("ipAddress") or ""
            if ip and not is_private_ip(ip):
                ips.add(ip)

            # PUBLIC_IP: flags
            for flag in record.get("_iocFlags") or []:
                if isinstance(flag, str) and flag.startswith("PUBLIC_IP:"):
                    candidate = flag[len("PUBLIC_IP:"):]
                    if candidate and not is_private_ip(candidate):
                        ips.add(candidate)

    return ips


# ── ip-api.com enrichment ─────────────────────────────────────────────────────

def _enrich_batch_ipapi(
    ips: list[str],
    session: requests.Session,
) -> dict[str, IPEnrichment]:
    """POST a batch of up to 100 IPs to ip-api.com and parse results."""
    results: dict[str, IPEnrichment] = {}

    payload = [{"query": ip, "fields": _IPAPI_FIELDS} for ip in ips]
    try:
        resp = session.post(_IPAPI_BATCH_URL, json=payload, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        for ip in ips:
            results[ip] = IPEnrichment(ip=ip, error=f"ip-api error: {exc!s}"[:120])
        return results

    for item in data:
        ip = item.get("query") or ""
        if not ip:
            continue
        if item.get("status") != "success":
            results[ip] = IPEnrichment(ip=ip, error=item.get("message", "lookup failed")[:80])
            continue

        asn_raw = item.get("as") or ""   # e.g. "AS15169 Google LLC"
        asn_num = asn_raw.split(" ")[0] if asn_raw else ""

        results[ip] = IPEnrichment(
            ip=ip,
            country_code=item.get("countryCode") or "",
            country_name=item.get("country") or "",
            city=item.get("city") or "",
            asn=asn_num,
            org=item.get("org") or "",
            isp=item.get("isp") or "",
            is_datacenter=bool(item.get("hosting")),
            is_proxy=bool(item.get("proxy")),
            is_tor=bool(item.get("tor")),
        )

    # Fill in any IPs missing from response
    for ip in ips:
        if ip not in results:
            results[ip] = IPEnrichment(ip=ip, error="no response from ip-api.com")

    return results


# ── AbuseIPDB enrichment ──────────────────────────────────────────────────────

def _enrich_single_abuseipdb(
    ip: str,
    api_key: str,
    session: requests.Session,
) -> tuple[int | None, int | None, str]:
    """
    Query AbuseIPDB for a single IP.

    Returns (abuse_score, abuse_reports, error_string).
    error_string is empty on success.
    """
    try:
        resp = session.get(
            _ABUSEIPDB_CHECK_URL,
            params={"ipAddress": ip, "maxAgeInDays": str(_ABUSEIPDB_MAX_AGE), "verbose": ""},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=15,
        )
        if resp.status_code == 429:
            return None, None, "AbuseIPDB rate limit hit"
        if resp.status_code == 401:
            return None, None, "AbuseIPDB: invalid API key"
        resp.raise_for_status()
        body = resp.json()
        d = body.get("data") or {}
        score   = d.get("abuseConfidenceScore")
        reports = d.get("totalReports")
        return (int(score) if score is not None else None,
                int(reports) if reports is not None else None,
                "")
    except Exception as exc:
        return None, None, str(exc)[:80]


# ── Main pipeline ─────────────────────────────────────────────────────────────

def enrich_ips_batch(
    ips: set[str],
    abuseipdb_key: str | None = None,
    on_progress: Callable[[str], None] | None = None,
) -> dict[str, IPEnrichment]:
    """
    Enrich a set of public IP addresses.

    1. ip-api.com batch (100 IPs/POST) — always runs.
    2. AbuseIPDB single-IP queries — only when abuseipdb_key is provided,
       throttled to one request per second to respect the free-tier limit.

    Args:
        ips:            Set of public IP address strings.
        abuseipdb_key:  AbuseIPDB API key (optional).
                        Register free at https://www.abuseipdb.com/register
        on_progress:    Optional callback called with a status string on each
                        batch / AbuseIPDB query.

    Returns:
        Dict keyed by IP string mapping to IPEnrichment dataclasses.
    """
    if not ips:
        return {}

    session = requests.Session()
    session.headers.update({"User-Agent": "cirrus-ir/1.0"})

    ip_list = sorted(ips)
    results: dict[str, IPEnrichment] = {}

    # ── Step 1: ip-api.com (batch) ────────────────────────────────────────────
    for i in range(0, len(ip_list), _IPAPI_BATCH_SIZE):
        batch = ip_list[i : i + _IPAPI_BATCH_SIZE]
        if on_progress:
            on_progress(f"ip-api.com: querying {len(batch)} IPs (batch {i // _IPAPI_BATCH_SIZE + 1})")
        batch_results = _enrich_batch_ipapi(batch, session)
        results.update(batch_results)

    # ── Step 2: AbuseIPDB (optional, throttled) ───────────────────────────────
    if abuseipdb_key:
        for idx, ip in enumerate(ip_list):
            if on_progress:
                on_progress(f"AbuseIPDB: checking {ip} ({idx + 1}/{len(ip_list)})")
            score, reports, err = _enrich_single_abuseipdb(ip, abuseipdb_key, session)
            if ip in results:
                results[ip].abuse_score   = score
                results[ip].abuse_reports = reports
                if err and not results[ip].error:
                    results[ip].error = err
            # Throttle — free tier supports ~1 request/second
            if idx < len(ip_list) - 1:
                time.sleep(_ABUSEIPDB_THROTTLE)

    return results


def run_enrichment(
    case_dir: Path,
    abuseipdb_key: str | None = None,
    on_progress: Callable[[str], None] | None = None,
) -> dict[str, dict]:
    """
    Full enrichment pipeline for a case directory.

    1. Extracts all public IPs from collector JSON files.
    2. Enriches via ip-api.com (+ optionally AbuseIPDB).
    3. Writes ip_enrichment.json to case_dir.

    Returns the dict that was written to ip_enrichment.json.
    """
    if on_progress:
        on_progress("Scanning case files for IP addresses...")

    ips = extract_ips_from_case(case_dir)

    if not ips:
        output: dict = {"ips": {}, "total_ips": 0, "suspicious_count": 0}
        (case_dir / "ip_enrichment.json").write_text(
            json.dumps(output, indent=2), encoding="utf-8"
        )
        return output

    if on_progress:
        on_progress(f"Found {len(ips)} unique public IP(s) — starting enrichment...")

    enriched = enrich_ips_batch(ips, abuseipdb_key=abuseipdb_key, on_progress=on_progress)

    # Serialize to JSON-safe dict
    ips_dict: dict[str, dict] = {}
    for ip, e in enriched.items():
        d = asdict(e)
        d["threat_summary"] = e.threat_summary
        d["is_suspicious"]  = e.is_suspicious
        ips_dict[ip] = d

    suspicious_count = sum(1 for e in enriched.values() if e.is_suspicious)

    output = {
        "case_dir":        str(case_dir),
        "total_ips":       len(enriched),
        "suspicious_count": suspicious_count,
        "abuseipdb_used":  bool(abuseipdb_key),
        "ips":             ips_dict,
    }

    out_path = case_dir / "ip_enrichment.json"
    out_path.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")

    if on_progress:
        on_progress(
            f"Enrichment complete — {len(enriched)} IPs, "
            f"{suspicious_count} suspicious. Written to {out_path.name}"
        )

    return output
