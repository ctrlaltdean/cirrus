"""
Tenant-Wide Threat Hunt

Performs a proactive sweep of the whole tenant without requiring a known
starting account. Surfaces suspicious patterns across sign-in logs, directory
audit events, and OAuth consent grants — ranked by signal count.

Hunt checks:
  signin_anomalies   — accounts with legacy auth, device code, impossible travel,
                       or high Identity Protection risk in recent sign-ins
  new_admin_accounts — accounts created recently that also appear in a privileged
                       directory role (potential attacker-created backdoor admin)
  oauth_risky_apps   — OAuth apps with high-risk scopes consented by multiple
                       users — signs of org-wide OAuth phishing or over-consent
  password_spray     — IP addresses with many failures across many distinct
                       accounts; flags IPs where a success also occurred

Usage:
    from cirrus.analysis.hunt import run_hunt
    report = run_hunt(token, days=30)
"""

from __future__ import annotations

from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable

import requests

GRAPH_BASE = "https://graph.microsoft.com/v1.0"

# Minimum thresholds
_SPRAY_MIN_TARGETS   = 5   # distinct accounts from one IP
_SPRAY_MIN_FAILURES  = 10  # total failures from one IP
_ADMIN_ROLES_DAYS    = 30  # look-back for new admin accounts
_RISKY_APP_MIN_USERS = 2   # min users for an app to appear in risky app list

# High-risk OAuth scopes (delegated permissions that grant broad access)
_HIGH_RISK_SCOPES: frozenset[str] = frozenset({
    "Mail.Read", "Mail.ReadWrite", "Mail.ReadBasic", "Mail.Send",
    "MailboxSettings.ReadWrite", "full_access_as_user",
    "Files.Read.All", "Files.ReadWrite.All",
    "Contacts.Read", "Contacts.ReadWrite",
    "Directory.Read.All", "Directory.ReadWrite.All",
    "User.Read.All", "User.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "offline_access",
})

# Privileged Entra ID roles (display names, lowercase)
_HIGH_PRIV_ROLES: frozenset[str] = frozenset({
    "global administrator", "privileged role administrator",
    "security administrator", "exchange administrator",
    "privileged authentication administrator", "authentication administrator",
    "user administrator", "application administrator",
    "cloud application administrator", "conditional access administrator",
    "global reader", "security reader",
})

# Suspicious sign-in protocol values
_SUSPICIOUS_PROTOCOLS: frozenset[str] = frozenset({"deviceCode", "ropc"})

# Legacy auth client strings
_LEGACY_AUTH: frozenset[str] = frozenset({
    "imap4", "pop3", "smtp", "mapi", "exchange activesync",
    "basic authentication", "other clients", "authenticated smtp",
    "exchange web services", "basic auth",
})


# ── Dataclasses ────────────────────────────────────────────────────────────────

@dataclass
class HuntSignal:
    """A single suspicious signal attached to a target account or app."""
    check: str        # which hunt check produced this signal
    severity: str     # high | medium | low
    detail: str       # human-readable description


@dataclass
class HuntTarget:
    """
    A suspicious account or app surfaced by the hunt.

    For user-related findings, `name` is the UPN.
    For app-related findings, `name` is the app display name.
    """
    name: str
    target_type: str           # user | app
    signals: list[HuntSignal] = field(default_factory=list)

    @property
    def signal_count(self) -> int:
        return len(self.signals)

    @property
    def max_severity(self) -> str:
        if any(s.severity == "high" for s in self.signals):
            return "high"
        if any(s.severity == "medium" for s in self.signals):
            return "medium"
        return "low"


@dataclass
class HuntReport:
    tenant: str
    days: int
    generated_at: str
    targets: list[HuntTarget] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def high_targets(self) -> list[HuntTarget]:
        return [t for t in self.targets if t.max_severity == "high"]

    @property
    def total_signals(self) -> int:
        return sum(t.signal_count for t in self.targets)


# ── API helpers ────────────────────────────────────────────────────────────────

def _get(session: requests.Session, url: str, params: dict | None = None) -> dict:
    resp = session.get(url, params=params, timeout=30)
    if resp.status_code == 403:
        raise PermissionError(f"403 Forbidden: {url}")
    if resp.status_code == 404:
        raise FileNotFoundError(f"404 Not Found: {url}")
    if resp.status_code in (400, 501):
        raise ValueError(f"HTTP {resp.status_code}: {url}")
    resp.raise_for_status()
    return resp.json()


def _collect_all(
    session: requests.Session,
    url: str,
    params: dict | None = None,
    max_records: int = 5000,
) -> list[dict]:
    """Follow @odata.nextLink to collect all pages, capped at max_records."""
    results: list[dict] = []
    next_url: str | None = url
    p = params
    while next_url and len(results) < max_records:
        data = _get(session, next_url, params=p if next_url == url else None)
        results.extend(data.get("value") or [])
        next_url = data.get("@odata.nextLink")
    return results[:max_records]


def _odata_dt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_dt(ts: str) -> datetime:
    if not ts:
        return datetime.min.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return datetime.min.replace(tzinfo=timezone.utc)


def _is_private_ip(ip: str) -> bool:
    if not ip:
        return True
    return (
        ip.startswith("10.") or ip.startswith("127.") or
        ip.startswith("169.254.") or ip.startswith("192.168.") or
        any(ip.startswith(f"172.{i}.") for i in range(16, 32))
    )


# ── Hunt checks ────────────────────────────────────────────────────────────────

def _hunt_signin_anomalies(
    session: requests.Session,
    start_dt: datetime,
) -> tuple[list[HuntTarget], str | None]:
    """
    Scan all sign-in logs for suspicious per-account patterns.

    Returns (targets, error_str). Targets are accounts with one or more of:
      - Suspicious auth protocol (device code, ROPC)
      - Legacy authentication client
      - Identity Protection risk (high/medium level or atRisk state)
      - Impossible travel (consecutive sign-ins from different countries ≤ 2h)
    """
    try:
        records = _collect_all(
            session,
            f"{GRAPH_BASE}/auditLogs/signIns",
            params={
                "$filter": f"createdDateTime ge {_odata_dt(start_dt)}",
                "$top": "999",
                "$select": (
                    "id,createdDateTime,userPrincipalName,ipAddress,"
                    "authenticationProtocol,clientAppUsed,location,"
                    "riskLevelAggregated,riskLevelDuringSignIn,riskState,"
                    "status"
                ),
            },
        )
    except PermissionError:
        return [], "signin_anomalies: AuditLog.Read.All / Entra ID P1 required"
    except Exception as exc:
        return [], f"signin_anomalies: {str(exc)[:120]}"

    # Group by user
    by_user: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        upn = r.get("userPrincipalName") or ""
        if upn:
            by_user[upn].append(r)

    targets: list[HuntTarget] = []

    for upn, user_records in by_user.items():
        signals: list[HuntSignal] = []

        for r in user_records:
            proto = r.get("authenticationProtocol") or ""
            if proto in _SUSPICIOUS_PROTOCOLS:
                signals.append(HuntSignal(
                    "signin_anomalies", "high",
                    f"Suspicious auth protocol: {proto}",
                ))

            client = (r.get("clientAppUsed") or "").lower().strip()
            if client in _LEGACY_AUTH:
                signals.append(HuntSignal(
                    "signin_anomalies", "medium",
                    f"Legacy auth client: {r.get('clientAppUsed')}",
                ))

            risk_level = (
                r.get("riskLevelAggregated") or
                r.get("riskLevelDuringSignIn") or "none"
            )
            if risk_level == "high":
                signals.append(HuntSignal(
                    "signin_anomalies", "high",
                    f"Identity Protection risk level: {risk_level}",
                ))
            elif risk_level == "medium":
                signals.append(HuntSignal(
                    "signin_anomalies", "medium",
                    f"Identity Protection risk level: {risk_level}",
                ))

            risk_state = r.get("riskState") or ""
            if risk_state in ("atRisk", "confirmedCompromised"):
                signals.append(HuntSignal(
                    "signin_anomalies", "high",
                    f"Identity Protection risk state: {risk_state}",
                ))

        # Impossible travel: consecutive sign-ins from different countries ≤ 2h
        sorted_recs = sorted(user_records, key=lambda r: _parse_dt(r.get("createdDateTime") or ""))
        for i in range(len(sorted_recs) - 1):
            r1, r2 = sorted_recs[i], sorted_recs[i + 1]
            c1 = (r1.get("location") or {}).get("countryOrRegion") or ""
            c2 = (r2.get("location") or {}).get("countryOrRegion") or ""
            if c1 and c2 and c1 != c2:
                dt1 = _parse_dt(r1.get("createdDateTime") or "")
                dt2 = _parse_dt(r2.get("createdDateTime") or "")
                diff_h = (dt2 - dt1).total_seconds() / 3600
                if 0 <= diff_h <= 2.0:
                    signals.append(HuntSignal(
                        "signin_anomalies", "high",
                        f"Impossible travel: {c1} → {c2} in {diff_h:.1f}h",
                    ))

        # Deduplicate by (severity, detail)
        seen: set[tuple[str, str]] = set()
        deduped: list[HuntSignal] = []
        for s in signals:
            key = (s.severity, s.detail)
            if key not in seen:
                seen.add(key)
                deduped.append(s)

        if deduped:
            targets.append(HuntTarget(name=upn, target_type="user", signals=deduped))

    return targets, None


def _hunt_new_admin_accounts(
    session: requests.Session,
    start_dt: datetime,
) -> tuple[list[HuntTarget], str | None]:
    """
    Find accounts created recently that hold a privileged directory role.

    An attacker who gains Global Admin access will often create a backdoor
    account and assign it a privileged role. This check surfaces any account
    created within the collection window that currently holds a high-priv role.
    """
    try:
        # Fetch all privileged role assignments
        role_members: dict[str, list[str]] = defaultdict(list)  # upn -> role names
        roles = _collect_all(
            session,
            f"{GRAPH_BASE}/directoryRoles",
            params={"$select": "id,displayName"},
        )
    except PermissionError:
        return [], "new_admin_accounts: Directory.Read.All required"
    except Exception as exc:
        return [], f"new_admin_accounts: {str(exc)[:120]}"

    for role in roles:
        role_name = (role.get("displayName") or "").lower()
        if role_name not in _HIGH_PRIV_ROLES:
            continue
        role_id = role.get("id") or ""
        if not role_id:
            continue
        try:
            members = _collect_all(
                session,
                f"{GRAPH_BASE}/directoryRoles/{role_id}/members",
                params={"$select": "id,userPrincipalName,createdDateTime,accountEnabled"},
            )
        except Exception:
            continue

        for member in members:
            upn = member.get("userPrincipalName") or ""
            if not upn:
                continue
            created_str = member.get("createdDateTime") or ""
            created_dt = _parse_dt(created_str)
            if created_dt >= start_dt:
                role_members[upn].append(role.get("displayName") or role_name)

    targets: list[HuntTarget] = []
    for upn, role_names in role_members.items():
        signals = [
            HuntSignal(
                "new_admin_accounts", "high",
                f"Recently created account holds privileged role: {', '.join(role_names)}",
            )
        ]
        targets.append(HuntTarget(name=upn, target_type="user", signals=signals))

    return targets, None


def _hunt_oauth_risky_apps(
    session: requests.Session,
) -> tuple[list[HuntTarget], str | None]:
    """
    Tenant-wide OAuth consent inventory — find apps with high-risk scopes
    consented by multiple users.

    Queries /oauth2PermissionGrants at tenant scope (no user filter). Groups
    grants by clientId, aggregates consented scopes and consenting users.
    Apps with a high-risk scope consented by >= _RISKY_APP_MIN_USERS users
    are reported as HuntTargets.
    """
    try:
        grants = _collect_all(
            session,
            f"{GRAPH_BASE}/oauth2PermissionGrants",
            params={"$top": "999"},
        )
    except PermissionError:
        return [], "oauth_risky_apps: Directory.Read.All required"
    except Exception as exc:
        return [], f"oauth_risky_apps: {str(exc)[:120]}"

    # Group by clientId
    by_client: dict[str, dict] = {}  # clientId -> {scopes: set, users: set, display_name: str}
    for grant in grants:
        client_id = grant.get("clientId") or ""
        if not client_id:
            continue
        if client_id not in by_client:
            by_client[client_id] = {
                "scopes": set(),
                "users": set(),
                "display_name": "",
            }
        scope_str = grant.get("scope") or ""
        for scope in scope_str.split():
            by_client[client_id]["scopes"].add(scope.strip())
        # principal is the user or service principal that consented
        principal_id = grant.get("principalId") or ""
        if principal_id:
            by_client[client_id]["users"].add(principal_id)
        consent_type = (grant.get("consentType") or "").lower()
        if consent_type == "allusers":
            # Admin consent for all users — treat as max exposure
            by_client[client_id]["users"].add("__allusers__")

    # Resolve display names for flagged apps
    targets: list[HuntTarget] = []
    for client_id, info in by_client.items():
        high_risk = info["scopes"] & _HIGH_RISK_SCOPES
        user_count = len(info["users"])
        all_users_consent = "__allusers__" in info["users"]

        if not high_risk:
            continue
        if user_count < _RISKY_APP_MIN_USERS and not all_users_consent:
            continue

        # Try to resolve the app name from service principals
        app_name = info["display_name"]
        if not app_name:
            try:
                sp_data = _collect_all(
                    session,
                    f"{GRAPH_BASE}/servicePrincipals",
                    params={
                        "$filter": f"appId eq '{client_id}'",
                        "$select": "displayName,appId",
                        "$top": "1",
                    },
                )
                app_name = (sp_data[0].get("displayName") or "") if sp_data else ""
            except Exception:
                pass
        app_label = app_name or client_id

        severity = "high" if all_users_consent else "medium"
        scope_list = ", ".join(sorted(high_risk)[:5])
        user_label = "all users (admin consent)" if all_users_consent else f"{user_count} user(s)"

        signals = [
            HuntSignal(
                "oauth_risky_apps", severity,
                f"High-risk scopes: {scope_list} — consented by {user_label}",
            )
        ]
        targets.append(HuntTarget(name=app_label, target_type="app", signals=signals))

    return targets, None


def _hunt_password_spray(
    session: requests.Session,
    start_dt: datetime,
) -> tuple[list[HuntTarget], str | None]:
    """
    Identify IP addresses performing password spray attacks.

    Flags IPs with >= _SPRAY_MIN_FAILURES failed sign-ins across
    >= _SPRAY_MIN_TARGETS distinct accounts. Elevates to HIGH when a
    successful sign-in from the same IP also exists (spray may have landed).

    Returns HuntTargets where `name` is the attacker IP address.
    """
    try:
        records = _collect_all(
            session,
            f"{GRAPH_BASE}/auditLogs/signIns",
            params={
                "$filter": f"createdDateTime ge {_odata_dt(start_dt)}",
                "$top": "999",
                "$select": "id,userPrincipalName,ipAddress,status,createdDateTime",
            },
        )
    except PermissionError:
        return [], "password_spray: AuditLog.Read.All / Entra ID P1 required"
    except Exception as exc:
        return [], f"password_spray: {str(exc)[:120]}"

    # Per-IP stats
    ip_failures: dict[str, set[str]] = defaultdict(set)  # ip -> set of upns
    ip_total_failures: dict[str, int] = defaultdict(int)
    ip_successes: dict[str, set[str]] = defaultdict(set)

    for r in records:
        ip = r.get("ipAddress") or ""
        if not ip or _is_private_ip(ip):
            continue
        upn = r.get("userPrincipalName") or ""
        status = r.get("status") or {}
        error_code = status.get("errorCode") or 0

        if error_code != 0:
            ip_total_failures[ip] += 1
            if upn:
                ip_failures[ip].add(upn)
        else:
            if upn:
                ip_successes[ip].add(upn)

    targets: list[HuntTarget] = []
    for ip, failed_upns in ip_failures.items():
        if (
            ip_total_failures[ip] < _SPRAY_MIN_FAILURES or
            len(failed_upns) < _SPRAY_MIN_TARGETS
        ):
            continue

        success_upns = ip_successes.get(ip, set())
        severity = "high" if success_upns else "medium"

        detail = (
            f"{ip_total_failures[ip]} failures across {len(failed_upns)} accounts"
        )
        if success_upns:
            detail += f" — {len(success_upns)} successful sign-in(s) from same IP"

        signals = [HuntSignal("password_spray", severity, detail)]
        targets.append(HuntTarget(name=ip, target_type="user", signals=signals))

    return targets, None


# ── Orchestrator ───────────────────────────────────────────────────────────────

def run_hunt(token: str, days: int = 30, tenant: str = "") -> HuntReport:
    """
    Run all tenant-wide hunt checks in parallel and return a HuntReport.

    Args:
        token:  Bearer token with appropriate Graph API permissions.
        days:   How many days back to scan (default 30).
        tenant: Tenant domain string for display in the report.

    Returns:
        HuntReport with all suspicious targets ranked by signal count.
    """
    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "ConsistencyLevel": "eventual",
    })

    start_dt = datetime.now(timezone.utc) - timedelta(days=days)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    report = HuntReport(tenant=tenant, days=days, generated_at=generated_at)

    # Checks that need start_dt
    dt_checks: list[tuple[str, Callable]] = [
        ("signin_anomalies", lambda: _hunt_signin_anomalies(session, start_dt)),
        ("new_admin_accounts", lambda: _hunt_new_admin_accounts(session, start_dt)),
        ("password_spray", lambda: _hunt_password_spray(session, start_dt)),
    ]
    # Checks that don't need start_dt
    static_checks: list[tuple[str, Callable]] = [
        ("oauth_risky_apps", lambda: _hunt_oauth_risky_apps(session)),
    ]
    all_checks = dt_checks + static_checks

    # Merge targets from all checks, aggregating signals per account name
    merged: dict[str, HuntTarget] = {}

    with ThreadPoolExecutor(max_workers=4) as pool:
        future_to_key = {pool.submit(fn): key for key, fn in all_checks}
        for future in as_completed(future_to_key):
            key = future_to_key[future]
            try:
                targets, error = future.result()
            except Exception as exc:
                report.errors.append(f"{key}: unexpected error — {str(exc)[:120]}")
                continue

            if error:
                report.errors.append(error)

            for t in targets:
                existing = merged.get(t.name)
                if existing:
                    existing.signals.extend(t.signals)
                else:
                    merged[t.name] = t

    # Sort by descending signal count, then by max_severity
    sev_rank = {"high": 2, "medium": 1, "low": 0}
    report.targets = sorted(
        merged.values(),
        key=lambda t: (sev_rank.get(t.max_severity, 0), t.signal_count),
        reverse=True,
    )

    return report
