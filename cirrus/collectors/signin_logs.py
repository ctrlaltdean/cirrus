"""
Collector: Entra ID Sign-In Logs

Endpoint: GET /auditLogs/signIns
Requires:  AuditLog.Read.All

Collects interactive and non-interactive sign-in events.
Supports filtering by user(s) and date range.

Key IOCs surfaced:
  - Legacy authentication protocols (IMAP, POP3, SMTP, EAS, MAPI, BasicAuth)
  - Suspicious auth flows: device code phishing, ROPC (bypasses MFA)
  - MFA not satisfied on a successful sign-in
  - Conditional Access policy failure
  - Microsoft Identity Protection risk signals (high/medium risk, risk detail)
  - Anonymous IP / Tor / known malicious IP (riskDetail)
  - Impossible travel — same user, different countries within N hours
  - Public IP address tagged on every record for threat intel lookup
  - Country tagged on every record for geographic pivot/filtering
"""

from __future__ import annotations

import math
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from cirrus.collectors.base import GRAPH_BASE, GraphCollector
from cirrus.utils.helpers import is_private_ip

# ── Legacy authentication client strings (clientAppUsed field) ───────────────
# These protocols do not support modern auth and cannot enforce MFA or CA.
_LEGACY_AUTH_CLIENTS: frozenset[str] = frozenset({
    "exchange activesync",
    "imap4",
    "pop3",
    "smtp",
    "mapi",
    "autodiscover",
    "exchange online powershell",
    "other clients",
    "authenticated smtp",
    "reporting services",
    "offline address book",
    "exchange web services",
    "basic authentication",
    "basic auth",
})

# ── Suspicious authentication protocols ──────────────────────────────────────
# deviceCode: used in token-theft phishing (attacker tricks user into entering
#             a device code that grants the attacker's session a token)
# ropc:       Resource Owner Password Credentials — submits credentials directly,
#             bypasses MFA and Conditional Access
_SUSPICIOUS_PROTOCOLS: frozenset[str] = frozenset({
    "deviceCode",
    "ropc",
})

# ── Microsoft Identity Protection riskDetail values ──────────────────────────
# Geolocation-related risk signals
_GEO_RISK_DETAILS: frozenset[str] = frozenset({
    "anonymizedIPAddress",    # Tor exit node, VPN, or anonymising proxy
    "maliciousIPAddress",     # IP on Microsoft's threat intel blocklist
    "impossibleTravel",       # Microsoft's own impossible-travel detection
    "newCountry",             # First sign-in from this country for the user
    "unfamiliarFeatures",     # Unusual location, device, or behaviour
    "malwareInfectedIPAddress",
})

# Identity/credential risk signals
_IDENTITY_RISK_DETAILS: frozenset[str] = frozenset({
    "leakedCredentials",
    "investigationsThreatIntelligence",
    "adminConfirmedSigninCompromised",
    "adminConfirmedUserCompromised",
    "anomalousToken",
    "tokenIssuerAnomaly",
    "suspiciousInboxForwarding",
    "mcasSuspiciousInboxManipulationRules",
    "onPremisesPasswordSpray",
    "suspiciousBrowser",
})

# How close two sign-ins must be (in hours) to trigger IMPOSSIBLE_TRAVEL
_IMPOSSIBLE_TRAVEL_HOURS = 2.0

# Minimum great-circle distance (km) to flag as impossible travel when
# coordinates are available. Prevents false positives for border cities.
_IMPOSSIBLE_TRAVEL_MIN_KM = 500


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in kilometres between two lat/lon points."""
    r = 6371.0  # Earth radius km
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lam = math.radians(lon2 - lon1)
    a = math.sin(d_phi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(d_lam / 2) ** 2
    return r * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def _parse_signin_dt(record: dict) -> datetime:
    """Parse createdDateTime from a sign-in record to a UTC-aware datetime."""
    raw = record.get("createdDateTime") or ""
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)


def _flag_signin(record: dict) -> list[str]:
    """
    Analyse a single sign-in record and return a list of IOC flag strings.

    Flags are designed to be informative on their own (parametric where
    useful) so analysts can filter/group without opening the raw record.
    """
    flags: list[str] = []

    status = record.get("status") or {}
    error_code = status.get("errorCode", 0)

    # ── Failed sign-in ────────────────────────────────────────────────────────
    if error_code != 0:
        reason = status.get("failureReason") or f"errorCode={error_code}"
        flags.append(f"FAILED_SIGNIN:{reason}")

    # ── Legacy authentication ─────────────────────────────────────────────────
    client_app = (record.get("clientAppUsed") or "").lower().strip()
    if client_app and client_app in _LEGACY_AUTH_CLIENTS:
        flags.append(f"LEGACY_AUTH:{record.get('clientAppUsed')}")

    # ── Suspicious auth protocols ─────────────────────────────────────────────
    auth_protocol = record.get("authenticationProtocol") or ""
    if auth_protocol in _SUSPICIOUS_PROTOCOLS:
        flags.append(f"SUSPICIOUS_AUTH_PROTOCOL:{auth_protocol}")

    # ── Single-factor success (successful sign-in, MFA not required) ──────────
    auth_req = record.get("authenticationRequirement") or ""
    if auth_req == "singleFactorAuthentication" and error_code == 0:
        flags.append("SINGLE_FACTOR_SUCCESS")

    # ── Conditional Access failure ────────────────────────────────────────────
    if record.get("conditionalAccessStatus") == "failure":
        flags.append("CA_POLICY_FAILURE")

    # ── Microsoft Identity Protection risk level ──────────────────────────────
    risk_level = (
        record.get("riskLevelAggregated")
        or record.get("riskLevelDuringSignIn")
        or "none"
    )
    if risk_level in ("high", "medium"):
        flags.append(f"RISK_LEVEL:{risk_level}")

    # riskState: atRisk / confirmedCompromised are the actionable states
    risk_state = record.get("riskState") or "none"
    if risk_state in ("atRisk", "confirmedCompromised"):
        flags.append(f"RISK_STATE:{risk_state}")

    # riskDetail: geo and identity signals
    risk_detail = record.get("riskDetail") or "none"
    if risk_detail != "none":
        if risk_detail in _GEO_RISK_DETAILS:
            flags.append(f"GEO_RISK:{risk_detail}")
        elif risk_detail in _IDENTITY_RISK_DETAILS:
            flags.append(f"IDENTITY_RISK:{risk_detail}")
        else:
            flags.append(f"RISK_DETAIL:{risk_detail}")

    # ── Flagged for review by Microsoft ──────────────────────────────────────
    if record.get("flaggedForReview"):
        flags.append("FLAGGED_FOR_REVIEW")

    # ── IP address (public IPs only — useful for threat intel lookups) ────────
    ip = record.get("ipAddress") or ""
    if ip and not is_private_ip(ip):
        flags.append(f"PUBLIC_IP:{ip}")

    # ── Geolocation — always tag country and city for pivot/filtering ─────────
    location = record.get("location") or {}
    country = location.get("countryOrRegion") or ""
    city = location.get("city") or ""
    if country:
        flags.append(f"COUNTRY:{country}")
    if city:
        flags.append(f"CITY:{city}")

    return flags


def _detect_impossible_travel(records: list[dict]) -> None:
    """
    Cross-record impossible travel detection.

    Groups records by user, sorts by time, then checks consecutive sign-ins
    for physical impossibility using two strategies:

    1. Coordinate-based (preferred): uses geoCoordinates (lat/lon) from the
       sign-in record to compute great-circle distance. Flags pairs where
       distance > 500 km and elapsed time < 2 h.

    2. Country-based (fallback): flags pairs from different countries within
       2 h when coordinates are not available.

    Appends IMPOSSIBLE_TRAVEL flags directly to each record's _iocFlags list.
    This supplements Microsoft's own impossibleTravel riskDetail, which
    requires Identity Protection licensing — this runs on raw sign-in data
    with no licensing dependency.
    """
    by_user: dict[str, list[dict]] = defaultdict(list)
    for record in records:
        upn = record.get("userPrincipalName") or ""
        if upn:
            by_user[upn].append(record)

    for upn, user_records in by_user.items():
        sorted_recs = sorted(user_records, key=_parse_signin_dt)

        for i in range(len(sorted_recs) - 1):
            r1 = sorted_recs[i]
            r2 = sorted_recs[i + 1]

            dt1 = _parse_signin_dt(r1)
            dt2 = _parse_signin_dt(r2)
            diff_hours = (dt2 - dt1).total_seconds() / 3600

            if diff_hours > _IMPOSSIBLE_TRAVEL_HOURS or diff_hours < 0:
                continue

            loc1 = r1.get("location") or {}
            loc2 = r2.get("location") or {}
            geo1 = loc1.get("geoCoordinates") or {}
            geo2 = loc2.get("geoCoordinates") or {}
            country1 = loc1.get("countryOrRegion") or ""
            country2 = loc2.get("countryOrRegion") or ""

            lat1 = geo1.get("latitude")
            lon1 = geo1.get("longitude")
            lat2 = geo2.get("latitude")
            lon2 = geo2.get("longitude")

            if lat1 is not None and lon1 is not None and lat2 is not None and lon2 is not None:
                # Coordinate-based: compute actual distance
                try:
                    dist_km = _haversine_km(float(lat1), float(lon1), float(lat2), float(lon2))
                except (TypeError, ValueError):
                    dist_km = 0.0
                if dist_km < _IMPOSSIBLE_TRAVEL_MIN_KM:
                    continue  # too close to be suspicious (e.g. border cities)
                loc_label1 = f"{loc1.get('city') or country1 or 'unknown'}"
                loc_label2 = f"{loc2.get('city') or country2 or 'unknown'}"
                flag = (
                    f"IMPOSSIBLE_TRAVEL:{loc_label1}->{loc_label2}"
                    f":{diff_hours:.1f}h:{int(dist_km)}km"
                )
            else:
                # Coordinate fallback: country comparison
                if not country1 or not country2 or country1 == country2:
                    continue
                flag = (
                    f"IMPOSSIBLE_TRAVEL:{country1}->{country2}"
                    f":{diff_hours:.1f}h"
                )

            r1["_iocFlags"].append(flag)
            r2["_iocFlags"].append(flag)


class SignInLogsCollector(GraphCollector):
    name = "signin_logs"

    def collect(
        self,
        days: int = 30,
        users: list[str] | None = None,
        start_dt: datetime | None = None,
        end_dt: datetime | None = None,
    ) -> list[dict]:
        """
        Collect sign-in logs, annotating each record with IOC flags.

        Args:
            days:     How many days back to collect (default 30).
                      Ignored when start_dt is provided.
            users:    List of UPNs to filter on. None = collect all users.
            start_dt: Explicit collection start (UTC). Overrides days.
            end_dt:   Explicit collection end (UTC). Adds an upper bound filter.

        Returns list of sign-in event dicts, each with an _iocFlags list.
        """
        filters = self._build_date_filter(start_dt, end_dt, days)

        if users:
            user_filters = " or ".join(
                f"userPrincipalName eq '{u}'" for u in users
            )
            filters.append(f"({user_filters})")

        params: dict[str, Any] = {
            "$filter": " and ".join(filters),
            "$top": 999,
        }

        # /auditLogs/signIns uses only standard equality/comparison filters
        # — no advanced queries needed.  Sending ConsistencyLevel: eventual
        # (set on the session for other endpoints) routes the request to
        # Graph's premium backend and returns 403 on non-P1 tenants.
        # Strip it for this call only.
        self.session.headers.pop("ConsistencyLevel", None)
        try:
            records = self._collect_all(f"{GRAPH_BASE}/auditLogs/signIns", params)
        finally:
            self.session.headers["ConsistencyLevel"] = "eventual"

        # Per-record flagging
        for record in records:
            record["_iocFlags"] = _flag_signin(record)

        # Cross-record impossible travel detection (appends to existing flags)
        _detect_impossible_travel(records)

        return records
