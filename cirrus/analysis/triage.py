"""
Quick Triage Engine

Runs a focused set of high-signal checks against a single user (or a small
list of users) and reports results directly to the terminal.  Every check
also returns the raw API records it fetched so the caller can write them to
a case folder for downstream analysis.

Checks (run in parallel):
  sign_ins        — recent authentications: locations, protocols, risk signals
  mfa_methods     — registered auth methods: recently added, high-persistence
  inbox_rules     — mailbox rules: forwarding, delete, hide
  mail_forwarding — SMTP-level forwarding: external forward, no local copy
  oauth_grants    — delegated permission grants: high-risk scopes
  devices         — registered devices: recent additions, personal/unmanaged
  audit_activity  — directory audit: MFA changes, password resets, role assigns
  risky_status    — Identity Protection risk state (best-effort, skips on no P2)

Each check returns a (CheckResult, list[dict]) tuple:
  CheckResult — status, summary, flags for terminal display and triage_report.json
  list[dict]  — raw Graph API records for writing to the case folder / SIEM

CheckResult status levels:
  clean    — nothing suspicious found
  warn     — medium-severity flags
  high     — high-severity flags (immediate attention warranted)
  error    — API call failed
  skipped  — check not applicable (e.g. license not available)
"""

from __future__ import annotations

import base64
import json as _json
import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable

import requests

GRAPH_BASE = "https://graph.microsoft.com/v1.0"

# ── Status ranking (for determining overall verdict) ──────────────────────────
_STATUS_RANK = {"high": 3, "warn": 2, "clean": 1, "skipped": 0, "error": 0}

# ── High-severity flag prefixes (copied from collector flag logic) ─────────────
_HIGH_FLAG_PREFIXES = (
    "HIGH_PERSISTENCE_METHOD", "SUSPICIOUS_AUTH_PROTOCOL", "IMPOSSIBLE_TRAVEL",
    "EXTERNAL_EMAIL_OTP", "USABLE_TEMP_ACCESS_PASS", "EXTERNAL_SMTP_FORWARD",
    "NO_LOCAL_COPY", "HIGH_PRIV_ROLE_ASSIGNED", "RISK_STATE:atRisk",
    "RISK_STATE:confirmedCompromised", "RISK_LEVEL:high", "GEO_RISK:",
    "ADMIN_PASSWORD_RESET", "APP_CONSENT_GRANTED",
)
_WARN_FLAG_PREFIXES = (
    "RECENTLY_ADDED", "RECENTLY_REGISTERED", "MULTIPLE_AUTHENTICATOR",
    "FORWARDS_TO:", "PERMANENT_DELETE", "HIGH_RISK_SCOPE:", "RISK_LEVEL:medium",
    "ROLE_ASSIGNMENT:", "MFA_METHOD_ADDED", "MULTIPLE_PHONE", "LEGACY_AUTH:",
    "SINGLE_FACTOR_SUCCESS", "FAILED_SIGNIN:", "MOVES_TO_HIDDEN_FOLDER:",
)

# High-risk OAuth scopes
_HIGH_RISK_SCOPES = frozenset({
    "Mail.Read", "Mail.ReadWrite", "Mail.ReadBasic", "Mail.Send",
    "MailboxSettings.ReadWrite", "full_access_as_user", "Contacts.Read",
    "Contacts.ReadWrite", "Files.Read.All", "Files.ReadWrite.All",
    "Directory.Read.All", "Directory.ReadWrite.All", "User.Read.All",
    "User.ReadWrite.All", "RoleManagement.ReadWrite.Directory", "offline_access",
})

_HIGH_PRIV_ROLES = frozenset({
    "global administrator", "privileged role administrator",
    "security administrator", "exchange administrator",
    "privileged authentication administrator", "authentication administrator",
    "user administrator", "application administrator",
    "cloud application administrator", "conditional access administrator",
})

# MFA method flags from @odata.type
_MFA_TYPE_MAP = {
    "#microsoft.graph.phoneAuthenticationMethod":               "phone",
    "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod": "authenticator_app",
    "#microsoft.graph.fido2AuthenticationMethod":               "fido2_key",
    "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod": "windows_hello",
    "#microsoft.graph.emailAuthenticationMethod":               "email_otp",
    "#microsoft.graph.passwordAuthenticationMethod":            "password",
    "#microsoft.graph.softwareOathAuthenticationMethod":        "software_oath",
    "#microsoft.graph.temporaryAccessPassAuthenticationMethod": "temporary_access_pass",
}
_HIGH_PERSISTENCE = frozenset({"fido2_key", "certificate"})


# ── Result dataclass ───────────────────────────────────────────────────────────

@dataclass
class CheckResult:
    label: str
    status: str            # clean | warn | high | error | skipped
    summary: str           # one-line summary
    detail: list[str] = field(default_factory=list)   # bullet points
    flags: list[str] = field(default_factory=list)    # IOC flag strings


@dataclass
class TriageReport:
    user: str
    tenant: str
    days: int
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        if any(c.status == "high" for c in self.checks):
            return "high"
        if any(c.status == "warn" for c in self.checks):
            return "warn"
        return "clean"

    @property
    def flagged_count(self) -> int:
        return sum(1 for c in self.checks if c.status in ("high", "warn"))


# ── API helpers ────────────────────────────────────────────────────────────────

def _get(session: requests.Session, url: str, params: dict | None = None) -> dict | list:
    resp = session.get(url, params=params, timeout=30)
    if resp.status_code == 403:
        try:
            err = resp.json().get("error", {})
            code = err.get("code", "")
            msg = (err.get("message") or "")[:120]
            detail = f"{code}: {msg}" if code else msg
        except Exception:
            detail = url
        raise PermissionError(f"403 {detail}".strip())
    if resp.status_code == 404:
        raise FileNotFoundError(f"404 Not Found: {url}")
    if resp.status_code == 400:
        raise ValueError(f"400 Bad Request: {url}")
    resp.raise_for_status()
    return resp.json()


def _collect_all(session: requests.Session, url: str, params: dict | None = None) -> list[dict]:
    """Follow @odata.nextLink to collect all pages."""
    results: list[dict] = []
    next_url: str | None = url
    p = params or {}
    while next_url:
        data = _get(session, next_url, params=p if next_url == url else None)
        results.extend(data.get("value") or [])
        next_url = data.get("@odata.nextLink")
    return results


def _parse_dt(ts: str) -> datetime:
    if not ts:
        return datetime.min.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return datetime.min.replace(tzinfo=timezone.utc)


def _odata_dt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _flag_status(flags: list[str]) -> str:
    if any(f.startswith(p) for f in flags for p in _HIGH_FLAG_PREFIXES):
        return "high"
    if any(f.startswith(p) for f in flags for p in _WARN_FLAG_PREFIXES):
        return "warn"
    return "clean"


def _is_private_ip(ip: str) -> bool:
    if not ip:
        return True
    return (
        ip.startswith("10.") or ip.startswith("127.") or
        ip.startswith("169.254.") or ip.startswith("192.168.") or
        any(ip.startswith(f"172.{i}.") for i in range(16, 32))
    )


# ── Individual checks ──────────────────────────────────────────────────────────

def _check_sign_ins(
    session: requests.Session, upn: str, start_dt: datetime
) -> tuple[CheckResult, list[dict]]:
    label = "Sign-in activity"
    try:
        params = {
            "$filter": (
                f"userPrincipalName eq '{upn}' and "
                f"createdDateTime ge {_odata_dt(start_dt)}"
            ),
            "$top": "50",
            "$orderby": "createdDateTime desc",
        }
        records = _collect_all(session, f"{GRAPH_BASE}/auditLogs/signIns", params)
    except PermissionError:
        return CheckResult(label, "skipped", "Requires Entra ID P1 / AuditLog.Read.All"), []
    except Exception as exc:
        return CheckResult(label, "error", str(exc)[:120]), []

    if not records:
        return CheckResult(label, "clean", f"No sign-ins in last {_days_label(start_dt)}"), records

    flags: list[str] = []
    countries: set[str] = set()
    failed = 0
    suspicious_protocols: list[str] = []
    legacy_auth: list[str] = []
    public_ips: list[str] = []
    risk_events: list[str] = []

    for r in records:
        status = r.get("status") or {}
        if (status.get("errorCode") or 0) != 0:
            failed += 1
            reason = (status.get("failureReason") or "")[:60]
            flags.append(f"FAILED_SIGNIN:{reason}")

        proto = r.get("authenticationProtocol") or ""
        if proto in ("deviceCode", "ropc"):
            suspicious_protocols.append(proto)
            flags.append(f"SUSPICIOUS_AUTH_PROTOCOL:{proto}")

        client = (r.get("clientAppUsed") or "").lower()
        if client in ("imap4", "pop3", "smtp", "mapi", "exchange activesync",
                      "basic authentication", "other clients", "authenticated smtp"):
            legacy_auth.append(r.get("clientAppUsed", client))
            flags.append(f"LEGACY_AUTH:{r.get('clientAppUsed', client)}")

        loc = r.get("location") or {}
        country = loc.get("countryOrRegion") or ""
        if country:
            countries.add(country)

        ip = r.get("ipAddress") or ""
        if ip and not _is_private_ip(ip) and ip not in public_ips:
            public_ips.append(ip)

        risk_level = r.get("riskLevelAggregated") or r.get("riskLevelDuringSignIn") or ""
        if risk_level in ("high", "medium"):
            flags.append(f"RISK_LEVEL:{risk_level}")
        risk_state = r.get("riskState") or ""
        if risk_state in ("atRisk", "confirmedCompromised"):
            flags.append(f"RISK_STATE:{risk_state}")
            risk_events.append(risk_state)

        auth_req = r.get("authenticationRequirement") or ""
        if auth_req == "singleFactorAuthentication" and (status.get("errorCode") or 0) == 0:
            flags.append("SINGLE_FACTOR_SUCCESS")

    # Impossible travel (consecutive sign-ins from different countries within 2h)
    sorted_recs = sorted(records, key=lambda r: _parse_dt(r.get("createdDateTime", "")))
    for i in range(len(sorted_recs) - 1):
        r1, r2 = sorted_recs[i], sorted_recs[i + 1]
        c1 = (r1.get("location") or {}).get("countryOrRegion") or ""
        c2 = (r2.get("location") or {}).get("countryOrRegion") or ""
        if c1 and c2 and c1 != c2:
            dt1 = _parse_dt(r1.get("createdDateTime", ""))
            dt2 = _parse_dt(r2.get("createdDateTime", ""))
            diff_h = (dt2 - dt1).total_seconds() / 3600
            if 0 <= diff_h <= 2.0:
                flags.append(f"IMPOSSIBLE_TRAVEL:{c1}->{c2}:{diff_h:.1f}h")

    # Deduplicate flags
    flags = list(dict.fromkeys(flags))
    check_status = _flag_status(flags)

    country_str = ", ".join(sorted(countries)[:5])
    summary = (
        f"{len(records)} sign-in(s) · "
        f"{len(countries)} country/countries ({country_str})"
        + (f" · {failed} failed" if failed else "")
    )

    detail: list[str] = []
    for f in flags[:8]:
        detail.append(f)
    if len(flags) > 8:
        detail.append(f"... +{len(flags)-8} more flags")
    if public_ips:
        detail.append(f"Public IPs: {', '.join(public_ips[:4])}")

    return CheckResult(label, check_status, summary, detail, flags), records


def _check_mfa_methods(
    session: requests.Session, upn: str, start_dt: datetime
) -> tuple[CheckResult, list[dict]]:
    label = "MFA methods"
    try:
        methods = _collect_all(
            session,
            f"{GRAPH_BASE}/users/{upn}/authentication/methods",
        )
    except PermissionError:
        return CheckResult(label, "skipped", "Requires UserAuthenticationMethod.Read.All"), []
    except Exception as exc:
        return CheckResult(label, "error", str(exc)[:120]), []

    if not methods:
        return CheckResult(label, "warn", "No authentication methods found — account has no MFA"), methods

    flags: list[str] = []
    type_counts: dict[str, int] = defaultdict(int)
    recently_added: list[str] = []

    for m in methods:
        odata = m.get("@odata.type") or ""
        mtype = _MFA_TYPE_MAP.get(odata.lower(), odata.split(".")[-1])
        type_counts[mtype] += 1

        if mtype in _HIGH_PERSISTENCE:
            flags.append(f"HIGH_PERSISTENCE_METHOD:{mtype}")

        created = m.get("createdDateTime") or ""
        if created:
            cdt = _parse_dt(created)
            if cdt >= start_dt:
                recently_added.append(f"{mtype} ({created[:10]})")
                flags.append(f"RECENTLY_ADDED:{created[:10]}")

        if mtype == "email_otp":
            email = m.get("emailAddress") or ""
            if email and "@" in email:
                upn_domain = upn.split("@")[-1].lower() if "@" in upn else ""
                email_domain = email.split("@")[-1].lower()
                if upn_domain and email_domain != upn_domain:
                    flags.append(f"EXTERNAL_EMAIL_OTP:{email_domain}")

        if mtype == "temporary_access_pass" and m.get("isUsable"):
            flags.append("USABLE_TEMP_ACCESS_PASS")

    if type_counts.get("authenticator_app", 0) > 1:
        flags.append(f"MULTIPLE_AUTHENTICATOR_APPS:{type_counts['authenticator_app']}")
    if type_counts.get("phone", 0) > 1:
        flags.append(f"MULTIPLE_PHONE_NUMBERS:{type_counts['phone']}")

    flags = list(dict.fromkeys(flags))
    check_status = _flag_status(flags) if flags else "clean"

    type_summary = ", ".join(f"{k}×{v}" if v > 1 else k for k, v in type_counts.items())
    summary = f"{len(methods)} method(s): {type_summary}"
    if recently_added:
        summary += f" — NEW: {', '.join(recently_added)}"

    detail = list(dict.fromkeys(flags))
    return CheckResult(label, check_status, summary, detail, flags), methods


def _check_inbox_rules(
    session: requests.Session, upn: str, start_dt: datetime
) -> tuple[CheckResult, list[dict]]:
    label = "Inbox rules"
    try:
        rules = _collect_all(
            session,
            f"{GRAPH_BASE}/users/{upn}/mailFolders/inbox/messageRules",
        )
    except PermissionError as exc:
        return CheckResult(label, "skipped", str(exc)[:160]), []
    except (FileNotFoundError, ValueError):
        return CheckResult(label, "skipped", "Mailbox not found or not Exchange-licensed"), []
    except Exception as exc:
        return CheckResult(label, "error", str(exc)[:120]), []

    return _run_inbox_analysis(rules)


def _run_inbox_analysis(rules: list[dict]) -> tuple[CheckResult, list[dict]]:
    """
    Pure analysis of a list of inbox rule dicts (Graph or normalized PS format).
    Extracted so it can be called by both the live check and the PS fallback.
    """
    label = "Inbox rules"
    if not rules:
        return CheckResult(label, "clean", "No inbox rules configured"), rules

    _HIDDEN = {"deleteditems", "junkemail", "rssfeedsroot", "drafts"}
    _FINANCE_KW = {"invoice", "wire", "payment", "transfer", "bank", "remittance",
                   "ach", "routing", "account number", "urgent", "confidential"}

    flags: list[str] = []
    suspicious: list[str] = []

    for rule in rules:
        actions = rule.get("actions") or {}
        conditions = rule.get("conditions") or {}

        for addr in (actions.get("forwardTo") or []):
            email = (addr.get("emailAddress") or {}).get("address") or ""
            if email:
                flags.append(f"FORWARDS_TO:{email}")
                suspicious.append(f"forwards to {email}")

        for addr in (actions.get("redirectTo") or []):
            email = (addr.get("emailAddress") or {}).get("address") or ""
            if email:
                flags.append(f"FORWARDS_TO:{email}")

        if actions.get("permanentDelete"):
            flags.append("PERMANENT_DELETE")
            suspicious.append("permanently deletes mail")

        move_folder = (actions.get("moveToFolder") or "").lower()
        if any(h in move_folder for h in _HIDDEN):
            flags.append(f"MOVES_TO_HIDDEN_FOLDER:{actions.get('moveToFolder')}")

        if actions.get("markAsRead") and (actions.get("forwardTo") or actions.get("permanentDelete")):
            flags.append("MARKS_AS_READ")

        for kw in ((conditions.get("bodyContains") or []) + (conditions.get("subjectContains") or [])):
            if kw.lower() in _FINANCE_KW:
                flags.append(f"SUSPICIOUS_KEYWORD:{kw}")

    flags = list(dict.fromkeys(flags))
    summary = f"{len(rules)} rule(s)"
    if suspicious:
        summary += f" — {'; '.join(suspicious[:3])}"
    return CheckResult(label, _flag_status(flags) if flags else "clean", summary,
                       list(dict.fromkeys(flags)), flags), rules


def _run_forwarding_analysis(upn: str, settings: dict) -> tuple[CheckResult, list[dict]]:
    """
    Pure analysis of a mailboxSettings dict (Graph or normalized PS format).
    Extracted so it can be called by both the live check and the PS fallback.
    """
    label = "Mail forwarding"
    fwd_smtp = settings.get("forwardingSmtpAddress") or ""
    fwd_addr = settings.get("forwardingAddress") or ""
    deliver_and_fwd = settings.get("deliverToMailboxAndForward", True)

    if not fwd_smtp and not fwd_addr:
        return CheckResult(label, "clean", "No forwarding configured"), [settings]

    flags: list[str] = []
    upn_domain = upn.split("@")[-1].lower() if "@" in upn else ""

    if fwd_smtp:
        fwd_domain = fwd_smtp.split("@")[-1].lower() if "@" in fwd_smtp else ""
        if fwd_domain and fwd_domain != upn_domain:
            flags.append(f"EXTERNAL_SMTP_FORWARD:{fwd_smtp}")
        else:
            flags.append(f"INTERNAL_SMTP_FORWARD:{fwd_smtp}")

    if fwd_addr:
        flags.append(f"FORWARDING_ADDRESS:{fwd_addr}")

    if not deliver_and_fwd:
        flags.append("NO_LOCAL_COPY:victim_receives_nothing")

    dest = fwd_smtp or fwd_addr
    summary = f"Forwarding to: {dest}" + (" (no local copy)" if not deliver_and_fwd else "")
    return CheckResult(label, _flag_status(flags) if flags else "warn", summary,
                       flags[:], flags), [settings]


def _check_mail_forwarding(
    session: requests.Session, upn: str, start_dt: datetime
) -> tuple[CheckResult, list[dict]]:
    label = "Mail forwarding"
    try:
        settings = _get(session, f"{GRAPH_BASE}/users/{upn}/mailboxSettings")
        if not isinstance(settings, dict):
            raise ValueError("Unexpected response")
    except PermissionError as exc:
        return CheckResult(label, "skipped", str(exc)[:160]), []
    except (FileNotFoundError, ValueError):
        return CheckResult(label, "skipped", "Mailbox not found or not Exchange-licensed"), []
    except Exception as exc:
        return CheckResult(label, "error", str(exc)[:120]), []

    return _run_forwarding_analysis(upn, settings)


def _check_oauth_grants(
    session: requests.Session, upn: str, start_dt: datetime
) -> tuple[CheckResult, list[dict]]:
    label = "OAuth grants"
    try:
        grants = _collect_all(
            session,
            f"{GRAPH_BASE}/users/{upn}/oauth2PermissionGrants",
            params={"$top": "999"},
        )
    except PermissionError:
        return CheckResult(label, "skipped", "Requires Directory.Read.All"), []
    except Exception as exc:
        return CheckResult(label, "error", str(exc)[:120]), []

    if not grants:
        return CheckResult(label, "clean", "No OAuth grants found"), grants

    flags: list[str] = []
    high_risk: list[str] = []

    for grant in grants:
        scope_str = grant.get("scope") or ""
        for scope in scope_str.split():
            if scope.strip() in _HIGH_RISK_SCOPES:
                flag = f"HIGH_RISK_SCOPE:{scope.strip()}"
                if flag not in flags:
                    flags.append(flag)
                    high_risk.append(scope.strip())

    check_status = _flag_status(flags) if flags else "clean"
    summary = f"{len(grants)} grant(s)"
    if high_risk:
        summary += f" — high-risk scopes: {', '.join(high_risk[:4])}"
    else:
        summary += " — no high-risk scopes"

    return CheckResult(label, check_status, summary, flags[:], flags), grants


def _check_devices(
    session: requests.Session, upn: str, start_dt: datetime
) -> tuple[CheckResult, list[dict]]:
    label = "Registered devices"
    try:
        devices = _collect_all(
            session,
            f"{GRAPH_BASE}/users/{upn}/registeredDevices",
            params={"$select": "id,displayName,operatingSystem,trustType,isManaged,isCompliant,registrationDateTime", "$top": "999"},
        )
    except PermissionError:
        return CheckResult(label, "skipped", "Requires Directory.Read.All"), []
    except Exception as exc:
        return CheckResult(label, "error", str(exc)[:120]), []

    if not devices:
        return CheckResult(label, "clean", "No registered devices"), devices

    flags: list[str] = []
    recently_added: list[str] = []

    for d in devices:
        reg_str = d.get("registrationDateTime") or ""
        if reg_str:
            try:
                reg_dt = _parse_dt(reg_str)
                if reg_dt >= start_dt:
                    name = d.get("displayName") or d.get("id", "")
                    recently_added.append(f"{name} ({reg_str[:10]})")
                    flags.append(f"RECENTLY_REGISTERED:{reg_str[:10]}")
            except ValueError:
                pass

        if (d.get("trustType") or "") == "Workplace":
            flags.append("PERSONAL_DEVICE")

        if d.get("isManaged") is False:
            flags.append("UNMANAGED_DEVICE")

    flags = list(dict.fromkeys(flags))
    check_status = _flag_status(flags) if flags else "clean"

    dev_names = ", ".join(
        d.get("displayName") or d.get("operatingSystem") or "unknown"
        for d in devices[:4]
    )
    summary = f"{len(devices)} device(s): {dev_names}"
    if recently_added:
        summary += f" — NEW: {', '.join(recently_added[:2])}"

    return CheckResult(label, check_status, summary, list(dict.fromkeys(flags)), flags), devices


def _check_audit_activity(
    session: requests.Session, upn: str, start_dt: datetime
) -> tuple[CheckResult, list[dict]]:
    label = "Directory audit"
    _MFA_ACTIVITIES = {
        "user registered security info", "user updated security info",
        "user deleted security info", "update user", "admin registered security info",
        "user registered all required security info",
    }
    _RESET_ACTIVITIES = {"reset user password", "change user password"}

    records: list[dict] = []
    try:
        # Filter by targetResources (changes TO this user)
        params = {
            "$filter": (
                f"activityDateTime ge {_odata_dt(start_dt)} and "
                f"targetResources/any(t:t/userPrincipalName eq '{upn}')"
            ),
            "$top": "50",
        }
        records = _collect_all(session, f"{GRAPH_BASE}/auditLogs/directoryAudits", params)
    except PermissionError:
        return CheckResult(label, "skipped", "Requires AuditLog.Read.All / Entra ID P1"), []
    except Exception:
        # Some tenants don't support the targetResources filter — try without
        try:
            params2 = {
                "$filter": f"activityDateTime ge {_odata_dt(start_dt)}",
                "$top": "50",
            }
            all_records = _collect_all(session, f"{GRAPH_BASE}/auditLogs/directoryAudits", params2)
            upn_lower = upn.lower()
            records = [
                r for r in all_records
                if any(
                    (res.get("userPrincipalName") or "").lower() == upn_lower
                    for res in (r.get("targetResources") or [])
                )
            ]
        except Exception as exc2:
            return CheckResult(label, "error", str(exc2)[:120]), []

    if not records:
        return CheckResult(label, "clean", f"No directory changes in last {_days_label(start_dt)}"), records

    flags: list[str] = []
    detail: list[str] = []

    for r in records:
        activity = (r.get("activityDisplayName") or "").lower()
        ts = (r.get("activityDateTime") or "")[:10]
        initiator = (((r.get("initiatedBy") or {}).get("user") or {}).get("userPrincipalName") or "")

        if any(a in activity for a in _MFA_ACTIVITIES):
            flags.append("MFA_METHOD_ADDED" if "register" in activity or "update" in activity else "MFA_METHOD_REMOVED")
            detail.append(f"MFA change: {r.get('activityDisplayName')} ({ts}) by {initiator or 'system'}")

        if any(a in activity for a in _RESET_ACTIVITIES):
            flags.append("ADMIN_PASSWORD_RESET")
            detail.append(f"Password reset ({ts}) by {initiator or 'system'}")

        if "add member to role" in activity or "add eligible member to role" in activity:
            role_name = ""
            for res in r.get("targetResources") or []:
                if (res.get("type") or "").lower() == "role":
                    role_name = res.get("displayName") or ""
            if role_name:
                if role_name.lower() in _HIGH_PRIV_ROLES:
                    flags.append(f"HIGH_PRIV_ROLE_ASSIGNED:{role_name}")
                    detail.append(f"HIGH-PRIV ROLE: {role_name} ({ts})")
                else:
                    flags.append(f"ROLE_ASSIGNMENT:{role_name}")
                    detail.append(f"Role assigned: {role_name} ({ts})")

        if "consent" in activity or "oauth2permissiongrant" in activity:
            flags.append("APP_CONSENT_GRANTED")
            detail.append(f"App consent: {r.get('activityDisplayName')} ({ts})")

    flags = list(dict.fromkeys(flags))
    detail = list(dict.fromkeys(detail))
    check_status = _flag_status(flags) if flags else "clean"

    summary = f"{len(records)} audit event(s) — {', '.join(list(dict.fromkeys(flags))[:4]) or 'no suspicious flags'}"
    return CheckResult(label, check_status, summary, detail[:6], flags), records


def _check_risky_status(
    session: requests.Session, upn: str, start_dt: datetime
) -> tuple[CheckResult, list[dict]]:
    label = "Identity Protection"
    try:
        data = _get(
            session,
            f"{GRAPH_BASE}/identityProtection/riskyUsers",
            params={"$filter": f"userPrincipalName eq '{upn}'", "$top": "5"},
        )
        users = data.get("value") or [] if isinstance(data, dict) else []
    except PermissionError:
        return CheckResult(label, "skipped", "Requires IdentityRiskyUser.Read.All (Entra ID P2)"), []
    except Exception as exc:
        return CheckResult(label, "skipped", f"Not available: {str(exc)[:80]}"), []

    if not users:
        return CheckResult(label, "clean", "User not found in risky users list"), users

    user = users[0]
    risk_level = user.get("riskLevel") or "none"
    risk_state = user.get("riskState") or "none"
    risk_detail = user.get("riskDetail") or "none"
    last_updated = (user.get("riskLastUpdatedDateTime") or "")[:10]

    flags: list[str] = []
    if risk_state in ("atRisk", "confirmedCompromised"):
        flags.append(f"RISK_STATE:{risk_state}")
    if risk_level in ("high", "medium"):
        flags.append(f"RISK_LEVEL:{risk_level}")
    if risk_detail not in ("none", "hidden", ""):
        flags.append(f"IDENTITY_RISK:{risk_detail}")

    check_status = _flag_status(flags) if flags else "clean"
    summary = f"Risk level: {risk_level}  |  State: {risk_state}"
    if last_updated:
        summary += f"  |  Last updated: {last_updated}"

    return CheckResult(label, check_status, summary, flags[:], flags), users


# ── Runner ─────────────────────────────────────────────────────────────────────

# Ordered list of (check_key, check_function) — key is also used as the output file stem
_CHECKS: list[tuple[str, Callable]] = [
    ("sign_ins",        _check_sign_ins),
    ("mfa_methods",     _check_mfa_methods),
    ("inbox_rules",     _check_inbox_rules),
    ("mail_forwarding", _check_mail_forwarding),
    ("oauth_grants",    _check_oauth_grants),
    ("devices",         _check_devices),
    ("audit_activity",  _check_audit_activity),
    ("risky_status",    _check_risky_status),
]


_MAILBOX_SCOPE = "MailboxSettings.Read"
_MAILBOX_CHECKS = frozenset({"inbox_rules", "mail_forwarding"})


def run_triage(
    token: str,
    upn: str,
    days: int = 7,
) -> tuple[TriageReport, dict[str, list[dict]], bool, bool]:
    """
    Run all triage checks for a single user.

    Returns:
        (TriageReport, raw_records, mailbox_scope_missing, mailbox_role_missing)

        raw_records maps each check key (e.g. "sign_ins", "mfa_methods")
        to the list of raw API records fetched during that check.

        mailbox_scope_missing — True when MailboxSettings.Read was not in
        the token at all (scope was never consented to).  Rare edge case
        since MailboxSettings.Read does not require admin consent.

        mailbox_role_missing — True when the scope IS in the token but
        the API still returned 403.  This means the running account lacks
        the Exchange Recipient Administrator role needed to read other
        users' mailbox data via delegated permissions.

    Checks run in parallel (ThreadPoolExecutor, 8 workers). Results are
    returned in the canonical check order regardless of completion order.
    """
    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "ConsistencyLevel": "eventual",
    })

    start_dt = datetime.now(timezone.utc) - timedelta(days=days)
    report = TriageReport(user=upn, tenant="", days=days)

    # Decode the token to check whether MailboxSettings.Read was granted.
    # The scope does NOT require admin consent — a user-level Accept in the
    # browser is sufficient.  If it's missing, that's an unusual edge case.
    token_scopes = decode_token_scopes(token)
    mailbox_scope_missing = bool(token_scopes) and _MAILBOX_SCOPE not in token_scopes

    results_map: dict[str, CheckResult] = {}
    raw_records: dict[str, list[dict]] = {}

    # Pre-populate mailbox checks as skipped only if the scope itself is absent.
    if mailbox_scope_missing:
        skip_msg = f"Skipped — {_MAILBOX_SCOPE} not in token (re-authenticate to re-consent)"
        results_map["inbox_rules"] = CheckResult("Inbox rules", "skipped", skip_msg)
        results_map["mail_forwarding"] = CheckResult("Mail forwarding", "skipped", skip_msg)
        raw_records["inbox_rules"] = []
        raw_records["mail_forwarding"] = []

    checks_to_run = [
        (key, fn) for key, fn in _CHECKS
        if key not in results_map
    ]

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {
            pool.submit(fn, session, upn, start_dt): key
            for key, fn in checks_to_run
        }
        for future in as_completed(futures):
            key = futures[future]
            try:
                check_result, records = future.result()
                results_map[key] = check_result
                raw_records[key] = records
            except Exception as exc:
                results_map[key] = CheckResult(key, "error", str(exc)[:120])
                raw_records[key] = []

    # Detect whether Graph 403'd on the mailbox checks (scope present but access denied).
    graph_mailbox_403 = (
        not mailbox_scope_missing and
        any(
            results_map.get(k, CheckResult("", "clean", "")).status == "skipped" and
            "403" in (results_map.get(k, CheckResult("", "clean", "")).summary or "")
            for k in _MAILBOX_CHECKS
        )
    )

    # ------------------------------------------------------------------ #
    # PowerShell fallback — runs only when Graph returned 403             #
    # ------------------------------------------------------------------ #
    mailbox_role_missing = False
    if graph_mailbox_403:
        try:
            from cirrus.utils.exchange_ps import run_triage_mailbox_ps
            ps_data = run_triage_mailbox_ps(upn)
        except Exception:
            ps_data = {"available": False, "error": "PowerShell fallback unavailable"}

        if ps_data.get("available"):
            # Re-run analysis with PS-sourced, normalized records
            ps_rules = _normalize_ps_inbox_rules(ps_data.get("inbox_rules") or [])
            ps_fwd   = _normalize_ps_mailbox_forwarding(ps_data.get("forwarding") or {})

            # Patch inbox_rules result
            ir_result, ir_records = _check_inbox_rules.__wrapped__(ps_rules) \
                if hasattr(_check_inbox_rules, "__wrapped__") \
                else _run_inbox_analysis(ps_rules)
            results_map["inbox_rules"] = ir_result
            raw_records["inbox_rules"] = ir_records

            # Patch mail_forwarding result
            fwd_result, fwd_records = _run_forwarding_analysis(upn, ps_fwd)
            results_map["mail_forwarding"] = fwd_result
            raw_records["mail_forwarding"] = fwd_records
        else:
            # PS not available or failed — flag role issue for the caller to display
            mailbox_role_missing = True
            ps_err = ps_data.get("error") or "PowerShell unavailable"
            for k, label in (("inbox_rules", "Inbox rules"), ("mail_forwarding", "Mail forwarding")):
                if results_map.get(k, CheckResult("", "clean", "")).status == "skipped":
                    results_map[k] = CheckResult(
                        label, "skipped",
                        f"403 (Graph) — PS fallback failed: {ps_err[:100]}",
                    )

    # Restore canonical order
    report.checks = [results_map[key] for key, _ in _CHECKS if key in results_map]
    return report, raw_records, mailbox_scope_missing, mailbox_role_missing


# ── Helpers ────────────────────────────────────────────────────────────────────

def _days_label(start_dt: datetime) -> str:
    diff = datetime.now(timezone.utc) - start_dt
    return f"{diff.days} day(s)"


def _ps_addr_to_graph(val: object) -> list[dict]:
    """
    Convert a PowerShell address field (str, dict, or list thereof) to the
    Graph messageRule `emailAddress` format used by the analysis functions.
    """
    def _one(item: object) -> str:
        if isinstance(item, str):
            return item.lstrip("smtp:").lstrip("SMTP:")
        if isinstance(item, dict):
            addr = (
                item.get("Address") or item.get("address") or
                item.get("RawString") or item.get("SmtpAddress") or ""
            )
            return str(addr).lstrip("smtp:").lstrip("SMTP:")
        return ""

    items = val if isinstance(val, list) else ([val] if val else [])
    return [
        {"emailAddress": {"address": a}}
        for item in items
        if (a := _one(item))
    ]


def _normalize_ps_inbox_rules(ps_rules: list[dict]) -> list[dict]:
    """
    Convert Get-InboxRule PowerShell output to Graph messageRule-compatible
    format so the existing _check_inbox_rules analysis logic can be reused.
    """
    normalized = []
    for r in ps_rules:
        normalized.append({
            "displayName": r.get("Name") or "",
            "isEnabled": r.get("Enabled", True),
            "actions": {
                "forwardTo":            _ps_addr_to_graph(r.get("ForwardTo")),
                "forwardAsAttachmentTo": _ps_addr_to_graph(r.get("ForwardAsAttachmentTo")),
                "redirectTo":           _ps_addr_to_graph(r.get("RedirectTo")),
                "permanentDelete":      bool(r.get("DeleteMessage", False)),
                "markAsRead":           bool(r.get("MarkAsRead", False)),
                "moveToFolder":         r.get("MoveToFolder") or "",
            },
            "conditions": {
                "subjectContains": r.get("SubjectContainsWords") or [],
                "bodyContains":    r.get("BodyContainsWords") or [],
            },
        })
    return normalized


def _normalize_ps_mailbox_forwarding(ps_mb: dict) -> dict:
    """
    Convert Get-Mailbox PowerShell forwarding output to Graph mailboxSettings
    format so the existing _check_mail_forwarding analysis logic can be reused.
    PS returns "smtp:user@domain.com"; Graph returns "user@domain.com".
    """
    fwd_smtp = (ps_mb.get("ForwardingSmtpAddress") or "")
    if fwd_smtp.lower().startswith("smtp:"):
        fwd_smtp = fwd_smtp[5:]
    return {
        "forwardingSmtpAddress":       fwd_smtp,
        "forwardingAddress":           ps_mb.get("ForwardingAddress") or "",
        "deliverToMailboxAndForward":  ps_mb.get("DeliverToMailboxAndForward", True),
    }


def decode_token_scopes(token: str) -> set[str]:
    """
    Decode the JWT access token and return the set of granted scopes.

    Reads the 'scp' claim from the token payload without verifying the
    signature — we only care what scopes were actually issued so we can
    skip checks that will 403 before making any API calls.

    Returns an empty set on any decode error (fail-open: let the API
    call surface the real error instead of blocking on a decode failure).
    """
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (4 - len(payload_b64) % 4)
        payload = _json.loads(base64.b64decode(payload_b64))
        scp = payload.get("scp", "")
        return set(scp.split()) if scp else set()
    except Exception:
        return set()
