"""
Investigation Report Generator

Produces a single self-contained HTML file (investigation_report.html) in the
case directory. The report combines:

  - Case metadata (tenant, workflow, analyst, date range)
  - Collection summary (records and IOC flag counts per collector)
  - Cross-collector correlation findings (from ioc_correlation.json)
  - IOC timeline — all flagged events sorted chronologically
  - Per-user summary — all flags aggregated per affected account
  - Per-collector tables — flagged records with key fields

The HTML file has no external dependencies and renders correctly offline.
All user-supplied data is HTML-escaped. The report is print-friendly.
"""

from __future__ import annotations

import html
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Collector display configuration ───────────────────────────────────────────

# For each collector: which fields to show in the flagged records table,
# what timestamp key to use for the timeline, and how to derive the user.
_COLLECTOR_CONFIG: dict[str, dict] = {
    "signin_logs": {
        "title": "Sign-In Logs",
        "filename": "signin_logs.json",
        "timestamp_key": "createdDateTime",
        "user_key": "userPrincipalName",
        "columns": [
            ("User",        "userPrincipalName"),
            ("Time (UTC)",  "createdDateTime"),
            ("IP",          "ipAddress"),
            ("Country",     "location.countryOrRegion"),
            ("App",         "clientAppUsed"),
            ("Protocol",    "authenticationProtocol"),
            ("Result",      "status.errorCode"),
        ],
    },
    "audit_logs": {
        "title": "Entra Audit Logs",
        "filename": "entra_audit_logs.json",
        "timestamp_key": "activityDateTime",
        "user_key": "_targetUser",   # synthesized during load
        "columns": [
            ("Activity",    "activityDisplayName"),
            ("Time (UTC)",  "activityDateTime"),
            ("Initiated By","initiatedBy.user.userPrincipalName"),
            ("Target",      "_targetUser"),
            ("Result",      "result"),
        ],
    },
    "mfa_methods": {
        "title": "MFA / Auth Methods",
        "filename": "mfa_methods.json",
        "timestamp_key": "createdDateTime",
        "user_key": "_sourceUser",
        "columns": [
            ("User",        "_sourceUser"),
            ("Method",      "_methodType"),
            ("Added",       "createdDateTime"),
            ("Phone #",     "phoneNumber"),
            ("Email",       "emailAddress"),
        ],
    },
    "users": {
        "title": "Users",
        "filename": "users.json",
        "timestamp_key": "createdDateTime",
        "user_key": "userPrincipalName",
        "columns": [
            ("UPN",         "userPrincipalName"),
            ("Display Name","displayName"),
            ("Type",        "userType"),
            ("Enabled",     "accountEnabled"),
            ("Created",     "createdDateTime"),
        ],
    },
    "registered_devices": {
        "title": "Registered Devices",
        "filename": "registered_devices.json",
        "timestamp_key": "registrationDateTime",
        "user_key": "_sourceUser",
        "columns": [
            ("User",        "_sourceUser"),
            ("Device",      "displayName"),
            ("OS",          "operatingSystem"),
            ("Trust Type",  "trustType"),
            ("Managed",     "isManaged"),
            ("Registered",  "registrationDateTime"),
        ],
    },
    "app_registrations": {
        "title": "App Registrations",
        "filename": "app_registrations.json",
        "timestamp_key": "createdDateTime",
        "user_key": "",
        "columns": [
            ("Display Name","displayName"),
            ("App ID",      "appId"),
            ("Created",     "createdDateTime"),
            ("Publisher",   "verifiedPublisher.displayName"),
        ],
    },
    "oauth_grants": {
        "title": "OAuth Grants",
        "filename": "oauth_grants.json",
        "timestamp_key": "",
        "user_key": "_sourceUser",
        "columns": [
            ("User",        "_sourceUser"),
            ("Scope",       "scope"),
            ("Grant Type",  "_grantType"),
            ("Client ID",   "clientId"),
        ],
    },
    "mailbox_rules": {
        "title": "Mailbox Rules",
        "filename": "mailbox_rules.json",
        "timestamp_key": "",
        "user_key": "_sourceUser",
        "columns": [
            ("User",        "_sourceUser"),
            ("Rule Name",   "displayName"),
            ("Enabled",     "isEnabled"),
            ("Forward To",  "actions.forwardTo"),
        ],
    },
    "mail_forwarding": {
        "title": "Mail Forwarding",
        "filename": "mail_forwarding.json",
        "timestamp_key": "",
        "user_key": "_sourceUser",
        "columns": [
            ("User",            "_sourceUser"),
            ("SMTP Forward",    "forwardingSmtpAddress"),
            ("Deliver+Forward", "deliverToMailboxAndForward"),
        ],
    },
    "pim_activations": {
        "title": "PIM Activations",
        "filename": "pim_activations.json",
        "timestamp_key": "activityDateTime",
        "user_key": "_targetUser",
        "columns": [
            ("Activity",    "activityDisplayName"),
            ("Time (UTC)",  "activityDateTime"),
            ("Initiated By","initiatedBy.user.userPrincipalName"),
            ("Target",      "_targetUser"),
            ("Result",      "result"),
        ],
    },
    "sp_signin_logs": {
        "title": "SP Sign-In Logs",
        "filename": "sp_signin_logs.json",
        "timestamp_key": "createdDateTime",
        "user_key": "servicePrincipalName",
        "columns": [
            ("App / SP",        "servicePrincipalName"),
            ("Time (UTC)",      "createdDateTime"),
            ("IP",              "ipAddress"),
            ("Country",         "location.countryOrRegion"),
            ("Resource",        "resourceDisplayName"),
            ("Credential",      "servicePrincipalCredentialType"),
            ("Result",          "status.errorCode"),
        ],
    },
}

_SEV_COLOR = {"high": "#ef4444", "medium": "#f97316", "low": "#6b7280"}
_SEV_BG    = {"high": "#fef2f2", "medium": "#fff7ed", "low": "#f8fafc"}


# ── Data loading ───────────────────────────────────────────────────────────────

def _read_case_meta(case_dir: Path) -> dict[str, str]:
    """Extract workflow/tenant metadata from case_audit.jsonl."""
    meta: dict[str, str] = {
        "tenant": "Unknown",
        "workflow": "Unknown",
        "start_date": "",
        "end_date": "",
        "analyst": "",
        "case_name": case_dir.name,
    }
    jsonl_path = case_dir / "case_audit.jsonl"
    if not jsonl_path.exists():
        return meta
    with jsonl_path.open(encoding="utf-8") as fh:
        for line in fh:
            try:
                entry = json.loads(line)
                if entry.get("action") == "WORKFLOW_START":
                    d = entry.get("details") or {}
                    meta["tenant"]     = d.get("tenant", meta["tenant"])
                    meta["workflow"]   = d.get("workflow", meta["workflow"])
                    meta["start_date"] = d.get("start_date", "")
                    meta["end_date"]   = d.get("end_date", "")
                    meta["analyst"]    = entry.get("analyst", "")
                    break
            except (json.JSONDecodeError, KeyError):
                pass
    return meta


def _load_data(case_dir: Path) -> dict[str, list[dict]]:
    """Load all available collector JSON files."""
    data: dict[str, list[dict]] = {}
    for key, cfg in _COLLECTOR_CONFIG.items():
        path = case_dir / "collection" / cfg["filename"]
        if not path.exists():
            path = case_dir / cfg["filename"]  # backward compat: flat structure
        if path.exists():
            try:
                records = json.loads(path.read_text(encoding="utf-8"))
                # Synthesize _targetUser for audit-style records
                if key in ("audit_logs", "pim_activations"):
                    for r in records:
                        targets = _audit_target_users(r)
                        r["_targetUser"] = targets[0] if targets else ""
                data[key] = records
            except (json.JSONDecodeError, OSError):
                data[key] = []
        else:
            data[key] = []
    return data


def _load_correlation(case_dir: Path) -> dict[str, Any]:
    path = case_dir / "ioc_correlation.json"
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {"summary": {}, "findings": [], "collectors_loaded": []}


def _load_enrichment(case_dir: Path) -> dict[str, Any]:
    path = case_dir / "ip_enrichment.json"
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _load_domain_enrichment(case_dir: Path) -> dict[str, Any]:
    path = case_dir / "domain_enrichment.json"
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _audit_target_users(record: dict) -> list[str]:
    upns: list[str] = []
    for res in record.get("targetResources") or []:
        if (res.get("type") or "").lower() == "user":
            upn = res.get("userPrincipalName") or ""
            if upn and "@" in upn:
                upns.append(upn)
    return upns


def _get_field(record: dict, dotpath: str) -> str:
    """Resolve a dot-notated field path from a record."""
    val = record
    for part in dotpath.split("."):
        if not isinstance(val, dict):
            return ""
        val = val.get(part)
        if val is None:
            return ""
    if isinstance(val, list):
        return ", ".join(str(v) for v in val[:3])
    return str(val) if val is not None else ""


def _flags(record: dict) -> list[str]:
    return record.get("_iocFlags") or []


# ── Statistics ─────────────────────────────────────────────────────────────────

def _build_stats(data: dict[str, list[dict]]) -> dict:
    stats: dict[str, dict] = {}
    total_records = 0
    total_flags = 0
    for key, records in data.items():
        if not records:
            continue
        flagged = [r for r in records if _flags(r)]
        flag_count = sum(len(_flags(r)) for r in records)
        stats[key] = {
            "title": _COLLECTOR_CONFIG[key]["title"],
            "total": len(records),
            "flagged": len(flagged),
            "flags": flag_count,
        }
        total_records += len(records)
        total_flags += flag_count
    return {"collectors": stats, "total_records": total_records, "total_flags": total_flags}


# ── Timeline ───────────────────────────────────────────────────────────────────

def _build_timeline(data: dict[str, list[dict]]) -> list[dict]:
    """
    Build a chronological list of flagged events from all collectors.
    Each entry: {timestamp, collector, user, summary, flags, severity}
    """
    events: list[dict] = []

    for key, records in data.items():
        cfg = _COLLECTOR_CONFIG.get(key, {})
        ts_key = cfg.get("timestamp_key") or ""
        user_key = cfg.get("user_key") or ""

        for r in records:
            f = _flags(r)
            if not f:
                continue
            ts_raw = r.get(ts_key, "") if ts_key else ""
            user = r.get(user_key, "") if user_key else ""

            # Determine worst severity from flags
            severity = _flag_severity(f)

            # Build a one-line summary
            summary = _record_summary(key, r, cfg)

            events.append({
                "timestamp": ts_raw,
                "timestamp_sort": _parse_ts_sort(ts_raw),
                "collector": key,
                "collector_title": cfg.get("title", key),
                "user": user,
                "summary": summary,
                "flags": f,
                "severity": severity,
            })

    events.sort(key=lambda e: e["timestamp_sort"])
    return events


def _parse_ts_sort(ts: str) -> datetime:
    if not ts:
        return datetime.min.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return datetime.min.replace(tzinfo=timezone.utc)


def _flag_severity(flags: list[str]) -> str:
    high_prefixes = (
        "HIGH_PERSISTENCE_METHOD", "SUSPICIOUS_AUTH_PROTOCOL", "IMPOSSIBLE_TRAVEL",
        "EXTERNAL_EMAIL_OTP", "USABLE_TEMP_ACCESS_PASS", "EXTERNAL_SMTP_FORWARD",
        "HIGH_PRIV_ROLE_ASSIGNED", "RISK_STATE:confirmedCompromised", "RISK_STATE:atRisk",
        "RISK_LEVEL:high", "GEO_RISK:", "IDENTITY_RISK:", "HAS_APP_PERMISSIONS",
        "ADMIN_PASSWORD_RESET", "APP_CONSENT_GRANTED", "CA_POLICY_DELETED",
    )
    medium_prefixes = (
        "RECENTLY_ADDED", "RECENTLY_CREATED", "RECENTLY_REGISTERED", "MULTIPLE_AUTHENTICATOR",
        "NO_LOCAL_COPY", "FORWARDS_TO:", "PERMANENT_DELETE", "HIGH_RISK_SCOPE:",
        "RECENTLY_CREATED", "RISK_LEVEL:medium", "ROLE_ASSIGNMENT:", "MULTIPLE_PHONE",
        "HAS_CLIENT_SECRETS", "MULTI_TENANT", "GUEST_ACCOUNT", "PUBLIC_IP:",
    )
    for f in flags:
        if any(f.startswith(p) for p in high_prefixes):
            return "high"
    for f in flags:
        if any(f.startswith(p) for p in medium_prefixes):
            return "medium"
    return "low"


def _record_summary(key: str, record: dict, cfg: dict) -> str:
    if key == "signin_logs":
        user = record.get("userPrincipalName", "")
        country = (record.get("location") or {}).get("countryOrRegion", "")
        app = record.get("clientAppUsed", "")
        return f"{user} — {country} via {app}" if country else f"{user} via {app}"
    if key == "audit_logs":
        activity = record.get("activityDisplayName", "")
        target = record.get("_targetUser", "")
        return f"{activity} → {target}" if target else activity
    if key == "mfa_methods":
        return f"{record.get('_sourceUser', '')} — {record.get('_methodType', '')}"
    if key == "users":
        return record.get("userPrincipalName", record.get("displayName", ""))
    if key == "registered_devices":
        return f"{record.get('_sourceUser', '')} — {record.get('displayName', '')} ({record.get('operatingSystem', '')})"
    if key == "app_registrations":
        return record.get("displayName", record.get("appId", ""))
    if key == "mailbox_rules":
        return f"{record.get('_sourceUser', '')} — {record.get('displayName', '')}"
    if key == "mail_forwarding":
        return f"{record.get('_sourceUser', '')} → {record.get('forwardingSmtpAddress', '')}"
    if key == "oauth_grants":
        scope = (record.get("scope") or "")[:60]
        return f"{record.get('_sourceUser', '')} — {scope}"
    return str(record.get("id", ""))


# ── User summary ───────────────────────────────────────────────────────────────

def _build_user_summary(data: dict[str, list[dict]]) -> dict[str, dict]:
    """Aggregate all IOC flags per user across all collectors."""
    users: dict[str, dict] = {}

    def _add(upn: str, collector: str, flags: list[str]) -> None:
        if not upn or not flags:
            return
        upn = upn.lower()
        if upn not in users:
            users[upn] = {"upn": upn, "collectors": defaultdict(list), "total_flags": 0}
        users[upn]["collectors"][collector].extend(flags)
        users[upn]["total_flags"] += len(flags)

    for key, records in data.items():
        cfg = _COLLECTOR_CONFIG.get(key, {})
        user_key = cfg.get("user_key") or ""
        for r in records:
            f = _flags(r)
            if not f:
                continue
            upn = r.get(user_key, "") if user_key else ""
            _add(upn, cfg.get("title", key), f)

    return dict(sorted(users.items(), key=lambda x: -x[1]["total_flags"]))


# ── HTML building blocks ───────────────────────────────────────────────────────

def _e(s: Any) -> str:
    """HTML-escape and stringify."""
    return html.escape(str(s) if s is not None else "")


def _flag_badge(flag: str) -> str:
    sev = _flag_severity([flag])
    color = _SEV_COLOR.get(sev, "#6b7280")
    return (
        f'<span class="flag-badge" style="background:{color}20;color:{color};'
        f'border:1px solid {color}40">{_e(flag)}</span>'
    )


def _sev_badge(sev: str) -> str:
    color = _SEV_COLOR.get(sev, "#6b7280")
    return (
        f'<span class="sev-badge" style="background:{color};color:#fff">'
        f'{_e(sev.upper())}</span>'
    )


def _ts_display(ts: str) -> str:
    if not ts:
        return "—"
    return ts[:19].replace("T", " ")


# ── HTML sections ──────────────────────────────────────────────────────────────

def _html_css() -> str:
    return """
<style>
:root {
  --bg: #f1f5f9; --card: #ffffff; --border: #e2e8f0;
  --text: #1e293b; --muted: #64748b; --navy: #0f172a;
  --high: #ef4444; --medium: #f97316; --low: #6b7280;
  --accent: #3b82f6; --flagged-row: #fffbeb;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
       background: var(--bg); color: var(--text); font-size: 14px; line-height: 1.5; }

/* Header */
.report-header { background: var(--navy); color: #fff; padding: 24px 32px; }
.report-header h1 { font-size: 20px; font-weight: 700; letter-spacing: 0.03em; }
.report-header .subtitle { color: #94a3b8; font-size: 13px; margin-top: 4px; }
.meta-grid { display: flex; flex-wrap: wrap; gap: 24px; margin-top: 16px; }
.meta-item { font-size: 12px; color: #94a3b8; }
.meta-item strong { color: #e2e8f0; display: block; font-size: 13px; }

/* Summary cards */
.summary-strip { display: flex; gap: 16px; padding: 20px 32px;
                  flex-wrap: wrap; border-bottom: 1px solid var(--border); }
.stat-card { background: var(--card); border: 1px solid var(--border); border-radius: 8px;
             padding: 16px 20px; min-width: 140px; flex: 1; }
.stat-card .stat-value { font-size: 28px; font-weight: 700; color: var(--navy); line-height: 1; }
.stat-card .stat-label { font-size: 12px; color: var(--muted); margin-top: 4px; }
.stat-card.high .stat-value { color: var(--high); }
.stat-card.flagged .stat-value { color: var(--medium); }

/* Tab navigation */
.tab-nav { display: flex; gap: 0; padding: 0 32px;
           background: var(--card); border-bottom: 2px solid var(--border);
           overflow-x: auto; }
.tab-btn { padding: 12px 18px; font-size: 13px; font-weight: 500; cursor: pointer;
           border: none; background: none; color: var(--muted); white-space: nowrap;
           border-bottom: 2px solid transparent; margin-bottom: -2px; transition: all 0.15s; }
.tab-btn:hover { color: var(--text); }
.tab-btn.active { color: var(--accent); border-bottom-color: var(--accent); }

/* Tab content */
.tab-content { display: none; padding: 24px 32px; }
.tab-content.active { display: block; }

/* Section headings */
.section-title { font-size: 16px; font-weight: 600; color: var(--navy);
                 margin-bottom: 16px; padding-bottom: 8px;
                 border-bottom: 1px solid var(--border); }

/* Correlation finding cards */
.finding-card { background: var(--card); border: 1px solid var(--border);
                border-radius: 8px; margin-bottom: 16px; overflow: hidden; }
.finding-header { display: flex; align-items: flex-start; gap: 12px;
                  padding: 16px 20px; cursor: pointer; user-select: none; }
.finding-header:hover { background: #f8fafc; }
.finding-id { font-weight: 700; color: var(--muted); font-size: 12px;
              min-width: 60px; padding-top: 2px; }
.finding-title-block { flex: 1; }
.finding-title { font-weight: 600; color: var(--navy); font-size: 14px; }
.finding-user { font-size: 12px; color: var(--muted); margin-top: 2px; font-family: monospace; }
.finding-toggle { color: var(--muted); font-size: 18px; transition: transform 0.2s; }
.finding-body { display: none; padding: 0 20px 20px; border-top: 1px solid var(--border); }
.finding-body.open { display: block; }
.finding-body .desc { margin: 14px 0; color: var(--text); }
.finding-body .rec { background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 6px;
                      padding: 10px 14px; color: #166534; font-size: 13px; margin-top: 12px; }
.finding-body .rec::before { content: "Recommendation: "; font-weight: 600; }

/* Evidence table */
.evidence-table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }
.evidence-table th { background: #f8fafc; padding: 7px 10px; text-align: left;
                      font-weight: 600; color: var(--muted); border-bottom: 1px solid var(--border); }
.evidence-table td { padding: 7px 10px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }
.evidence-table tr:last-child td { border-bottom: none; }
.collector-tag { display: inline-block; background: #eff6ff; color: #1d4ed8;
                 padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: 500; }

/* Timeline */
.timeline { position: relative; padding-left: 28px; }
.timeline::before { content: ""; position: absolute; left: 8px; top: 0; bottom: 0;
                     width: 2px; background: var(--border); }
.tl-event { position: relative; margin-bottom: 12px; }
.tl-dot { position: absolute; left: -24px; top: 4px; width: 12px; height: 12px;
          border-radius: 50%; border: 2px solid var(--card); }
.tl-card { background: var(--card); border: 1px solid var(--border); border-radius: 6px;
           padding: 10px 14px; }
.tl-card:hover { border-color: #cbd5e1; }
.tl-meta { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-bottom: 4px; }
.tl-ts { font-size: 11px; color: var(--muted); font-family: monospace; }
.tl-user { font-size: 12px; font-weight: 500; font-family: monospace; }
.tl-summary { font-size: 13px; color: var(--text); }
.tl-flags { margin-top: 6px; display: flex; flex-wrap: wrap; gap: 4px; }

/* Flag badges */
.flag-badge { display: inline-block; padding: 1px 6px; border-radius: 4px;
              font-size: 11px; font-family: monospace; font-weight: 500; }
.sev-badge { display: inline-block; padding: 2px 8px; border-radius: 4px;
             font-size: 11px; font-weight: 700; letter-spacing: 0.04em; }

/* Collector tables */
.collector-section { margin-bottom: 32px; }
.collector-section h3 { font-size: 14px; font-weight: 600; color: var(--navy);
                         margin-bottom: 10px; }
.data-table { width: 100%; border-collapse: collapse; font-size: 13px;
              table-layout: auto; }
.data-table th { background: #f8fafc; padding: 8px 10px; text-align: left;
                 font-weight: 600; color: var(--muted); border-bottom: 2px solid var(--border);
                 white-space: nowrap; }
.data-table td { padding: 7px 10px; border-bottom: 1px solid #f1f5f9;
                 vertical-align: top; max-width: 300px; overflow: hidden;
                 text-overflow: ellipsis; white-space: nowrap; font-family: monospace;
                 font-size: 12px; }
.data-table tr.flagged-row { background: var(--flagged-row); }
.data-table tr:hover td { background: #f8fafc; }
.flags-cell { white-space: normal; max-width: 400px; }
.no-data { color: var(--muted); font-style: italic; padding: 12px 0; }

/* User summary table */
.user-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.user-table th { background: #f8fafc; padding: 8px 12px; text-align: left;
                 font-weight: 600; color: var(--muted);
                 border-bottom: 2px solid var(--border); }
.user-table td { padding: 8px 12px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }
.user-upn { font-family: monospace; font-weight: 600; color: var(--navy); }
.collector-flags { margin-bottom: 4px; }
.collector-name { font-size: 11px; color: var(--muted); display: inline-block;
                  min-width: 140px; }

/* Footer */
.report-footer { padding: 20px 32px; color: var(--muted); font-size: 12px;
                 border-top: 1px solid var(--border); margin-top: 16px; }

/* Print */
@media print {
  .tab-nav { display: none; }
  .tab-content { display: block !important; }
  .finding-body { display: block !important; }
  .report-header { background: #000 !important; -webkit-print-color-adjust: exact; }
  body { background: white; }
}
</style>"""


def _html_js() -> str:
    return """
<script>
function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  document.querySelector('[data-tab="' + tabId + '"]').classList.add('active');
  document.getElementById(tabId).classList.add('active');
}
function toggleFinding(id) {
  const body = document.getElementById('fb-' + id);
  const icon = document.getElementById('fi-' + id);
  const open = body.classList.toggle('open');
  icon.textContent = open ? '▲' : '▼';
}
</script>"""


def _html_header(meta: dict, stats: dict, corr: dict) -> str:
    date_range = ""
    if meta["start_date"] and meta["end_date"]:
        date_range = f"{meta['start_date']} → {meta['end_date']}"
    elif meta["start_date"]:
        date_range = f"from {meta['start_date']}"

    total_records = stats["total_records"]
    total_flags = stats["total_flags"]
    finding_count = len(corr.get("findings") or [])
    high_count = (corr.get("summary") or {}).get("high", 0)
    affected = len((corr.get("summary") or {}).get("affected_users") or [])

    sev_class = "high" if high_count else ("flagged" if finding_count else "")

    return f"""
<div class="report-header">
  <h1>CIRRUS — Investigation Report</h1>
  <div class="subtitle">Cloud Incident Response &amp; Reconnaissance Utility Suite</div>
  <div class="meta-grid">
    <div class="meta-item"><strong>{_e(meta['case_name'])}</strong>Case</div>
    <div class="meta-item"><strong>{_e(meta['tenant'])}</strong>Tenant</div>
    <div class="meta-item"><strong>{_e(meta['workflow'].upper())}</strong>Workflow</div>
    {f'<div class="meta-item"><strong>{_e(date_range)}</strong>Date Range</div>' if date_range else ''}
    {f'<div class="meta-item"><strong>{_e(meta["analyst"])}</strong>Analyst</div>' if meta['analyst'] else ''}
    <div class="meta-item"><strong>{_e(meta.get("generated_at",""))}</strong>Generated</div>
  </div>
</div>

<div class="summary-strip">
  <div class="stat-card">
    <div class="stat-value">{total_records:,}</div>
    <div class="stat-label">Total Records</div>
  </div>
  <div class="stat-card flagged">
    <div class="stat-value">{total_flags:,}</div>
    <div class="stat-label">IOC Flags</div>
  </div>
  <div class="stat-card {sev_class}">
    <div class="stat-value">{finding_count}</div>
    <div class="stat-label">Correlation Findings</div>
  </div>
  <div class="stat-card">
    <div class="stat-value">{affected}</div>
    <div class="stat-label">Affected Users</div>
  </div>
  {_collector_stat_cards(stats)}
</div>"""


def _collector_stat_cards(stats: dict) -> str:
    parts: list[str] = []
    for key, s in stats["collectors"].items():
        if s["flagged"] > 0:
            parts.append(
                f'<div class="stat-card">'
                f'<div class="stat-value" style="font-size:20px">{s["flagged"]}</div>'
                f'<div class="stat-label">{_e(s["title"])} flagged</div>'
                f'</div>'
            )
    return "\n".join(parts)


def _html_tab_nav(data: dict, corr: dict, timeline: list, enrichment: dict | None = None, domain_enrichment: dict | None = None) -> str:
    findings = corr.get("findings") or []
    tabs = [("correlation", f"Correlation ({len(findings)})"),
            ("timeline",    f"Timeline ({len(timeline)})"),
            ("users",       "Users")]
    if findings:
        high_n = sum(1 for f in findings if f.get("severity") == "high")
        rem_label = f"Remediation ({len(findings)}"
        if high_n:
            rem_label += f", {high_n}⚠"
        rem_label += ")"
        tabs.append(("remediation", rem_label))
    if enrichment and enrichment.get("total_ips", 0) > 0:
        suspicious = enrichment.get("suspicious_count", 0)
        label = f"IP Enrichment ({enrichment['total_ips']} IPs"
        if suspicious:
            label += f", {suspicious}⚠"
        label += ")"
        tabs.append(("ip_enrichment", label))
    if domain_enrichment and domain_enrichment.get("total_domains", 0) > 0:
        d_susp = domain_enrichment.get("suspicious_count", 0)
        d_label = f"Domains ({domain_enrichment['total_domains']}"
        if d_susp:
            d_label += f", {d_susp}⚠"
        d_label += ")"
        tabs.append(("domain_enrichment", d_label))
    for key in _COLLECTOR_CONFIG:
        if data.get(key):
            cfg = _COLLECTOR_CONFIG[key]
            total = len(data[key])
            flagged = sum(1 for r in data[key] if _flags(r))
            label = f"{cfg['title']} ({flagged}⚑ / {total})"
            tabs.append((f"col_{key}", label))

    first = True
    parts: list[str] = []
    for tab_id, label in tabs:
        active = "active" if first else ""
        parts.append(
            f'<button class="tab-btn {active}" data-tab="{tab_id}" '
            f'onclick="switchTab(\'{tab_id}\')">{_e(label)}</button>'
        )
        first = False
    return f'<nav class="tab-nav">{"".join(parts)}</nav>'


def _html_correlation_tab(corr: dict) -> str:
    findings = corr.get("findings") or []
    if not findings:
        return (
            '<div class="tab-content active" id="correlation">'
            '<div class="section-title">Correlation Findings</div>'
            '<p class="no-data">No cross-collector findings detected.</p>'
            '</div>'
        )

    cards: list[str] = []
    for i, f in enumerate(findings):
        sev = f.get("severity", "low")
        color = _SEV_COLOR.get(sev, "#6b7280")
        bg = _SEV_BG.get(sev, "#f8fafc")
        evidence_rows = "".join(
            f'<tr>'
            f'<td><span class="collector-tag">{_e(ev.get("collector",""))}</span></td>'
            f'<td style="font-family:monospace;white-space:nowrap">{_e(_ts_display(ev.get("timestamp","")))}</td>'
            f'<td>{_e(ev.get("summary",""))}</td>'
            f'</tr>'
            for ev in (f.get("evidence") or [])
        )
        flag_badges = " ".join(_flag_badge(fl) for fl in (f.get("ioc_flags") or [])[:8])
        mitre = f.get("mitre_techniques") or []
        mitre_html = ""
        if mitre:
            badges = " ".join(
                f'<span class="flag-badge" style="background:#eff6ff;color:#1d4ed8;'
                f'border:1px solid #bfdbfe;font-family:sans-serif">{_e(t)}</span>'
                for t in mitre
            )
            mitre_html = f'<div style="margin-top:8px"><span style="font-size:11px;color:var(--muted);font-weight:600">MITRE ATT&amp;CK&nbsp;</span>{badges}</div>'
        cards.append(f"""
<div class="finding-card" style="border-left:4px solid {color}">
  <div class="finding-header" onclick="toggleFinding({i})" style="background:{bg}20">
    <div class="finding-id">{_e(f.get('id',''))}</div>
    <div class="finding-title-block">
      <div class="finding-title">{_sev_badge(sev)} &nbsp;{_e(f.get('title',''))}</div>
      {f'<div class="finding-user">{_e(f.get("user",""))}</div>' if f.get('user') else ''}
    </div>
    <div class="finding-toggle" id="fi-{i}">▼</div>
  </div>
  <div class="finding-body" id="fb-{i}">
    <p class="desc">{_e(f.get('description',''))}</p>
    {'<div style="margin-top:8px">'+flag_badges+'</div>' if flag_badges else ''}
    {mitre_html}
    {f'<table class="evidence-table"><thead><tr><th>Collector</th><th>Timestamp</th><th>Summary</th></tr></thead><tbody>{evidence_rows}</tbody></table>' if evidence_rows else ''}
    <div class="rec">{_e(f.get('recommendation',''))}</div>
  </div>
</div>""")

    return (
        f'<div class="tab-content active" id="correlation">'
        f'<div class="section-title">Correlation Findings — {len(findings)} finding(s)</div>'
        + "".join(cards)
        + "</div>"
    )


def _html_timeline_tab(timeline: list) -> str:
    if not timeline:
        return (
            '<div class="tab-content" id="timeline">'
            '<div class="section-title">IOC Timeline</div>'
            '<p class="no-data">No flagged events found.</p>'
            '</div>'
        )

    events_html: list[str] = []
    for ev in timeline:
        sev = ev["severity"]
        color = _SEV_COLOR.get(sev, "#6b7280")
        flag_badges = " ".join(_flag_badge(f) for f in ev["flags"][:5])
        if len(ev["flags"]) > 5:
            flag_badges += f' <span style="color:var(--muted);font-size:11px">+{len(ev["flags"])-5} more</span>'
        events_html.append(f"""
<div class="tl-event">
  <div class="tl-dot" style="background:{color}"></div>
  <div class="tl-card">
    <div class="tl-meta">
      <span class="tl-ts">{_e(_ts_display(ev['timestamp']))}</span>
      <span class="collector-tag">{_e(ev['collector_title'])}</span>
      {f'<span class="tl-user">{_e(ev["user"])}</span>' if ev['user'] else ''}
      {_sev_badge(sev)}
    </div>
    <div class="tl-summary">{_e(ev['summary'])}</div>
    <div class="tl-flags">{flag_badges}</div>
  </div>
</div>""")

    return (
        f'<div class="tab-content" id="timeline">'
        f'<div class="section-title">IOC Timeline — {len(timeline)} flagged event(s)</div>'
        f'<div class="timeline">{"".join(events_html)}</div>'
        f'</div>'
    )


def _html_users_tab(user_summary: dict) -> str:
    if not user_summary:
        return (
            '<div class="tab-content" id="users">'
            '<div class="section-title">Affected Users</div>'
            '<p class="no-data">No users with IOC flags found.</p>'
            '</div>'
        )

    rows: list[str] = []
    for upn, info in user_summary.items():
        flags_html_parts: list[str] = []
        for collector_name, flags in info["collectors"].items():
            unique_flags = list(dict.fromkeys(flags))
            badges = " ".join(_flag_badge(f) for f in unique_flags[:6])
            flags_html_parts.append(
                f'<div class="collector-flags">'
                f'<span class="collector-name">{_e(collector_name)}</span>{badges}'
                f'</div>'
            )
        rows.append(
            f'<tr><td class="user-upn">{_e(upn)}</td>'
            f'<td style="text-align:center">{info["total_flags"]}</td>'
            f'<td class="flags-cell">{"".join(flags_html_parts)}</td></tr>'
        )

    return (
        '<div class="tab-content" id="users">'
        '<div class="section-title">Affected Users</div>'
        '<table class="user-table"><thead><tr>'
        '<th>User (UPN)</th><th>Total Flags</th><th>Flags by Collector</th>'
        '</tr></thead><tbody>'
        + "".join(rows)
        + "</tbody></table></div>"
    )


def _html_collector_tab(key: str, records: list[dict]) -> str:
    cfg = _COLLECTOR_CONFIG[key]
    tab_id = f"col_{key}"

    flagged = [r for r in records if _flags(r)]
    unflagged_count = len(records) - len(flagged)

    columns = cfg["columns"]

    if not flagged:
        return (
            f'<div class="tab-content" id="{tab_id}">'
            f'<div class="section-title">{_e(cfg["title"])}</div>'
            f'<p class="no-data">{len(records)} record(s) collected — no IOC flags.</p>'
            f'</div>'
        )

    # Table header
    header_cells = "".join(f"<th>{_e(col[0])}</th>" for col in columns)
    header_cells += "<th>IOC Flags</th>"

    rows: list[str] = []
    for r in flagged:
        cells = "".join(
            f'<td title="{_e(_get_field(r, col[1]))}">{_e(_get_field(r, col[1])[:60])}</td>'
            for col in columns
        )
        flag_badges = " ".join(_flag_badge(f) for f in _flags(r))
        rows.append(f'<tr class="flagged-row">{cells}<td class="flags-cell">{flag_badges}</td></tr>')

    note = (
        f'<p style="font-size:12px;color:var(--muted);margin-top:8px">'
        f'{unflagged_count:,} additional unflagged record(s) not shown — '
        f'see {_e(cfg["filename"])} for full dataset.</p>'
        if unflagged_count else ""
    )

    return (
        f'<div class="tab-content" id="{tab_id}">'
        f'<div class="section-title">{_e(cfg["title"])} — {len(flagged)} flagged of {len(records)} total</div>'
        f'<table class="data-table">'
        f'<thead><tr>{header_cells}</tr></thead>'
        f'<tbody>{"".join(rows)}</tbody>'
        f'</table>'
        f'{note}'
        f'</div>'
    )


def _html_remediation_tab(corr: dict) -> str:
    """
    Render a remediation checklist tab.

    Extracts the `recommendation` field from every correlation finding and
    supplements it with rule-specific additional action items.  Items are
    sorted HIGH → MEDIUM → LOW and rendered as interactive checkboxes so
    analysts can tick off actions as they work through the investigation.
    """
    findings = corr.get("findings") or []
    if not findings:
        return (
            '<div class="tab-content" id="remediation">'
            '<div class="section-title">Remediation Checklist</div>'
            '<p class="no-data">No correlation findings — no remediation actions required.</p>'
            '</div>'
        )

    # Extra per-rule action items supplementing the `recommendation` field
    _RULE_ACTIONS: dict[str, list[str]] = {
        "suspicious_signin_then_persistence": [
            "Revoke all active sessions: az ad user revoke-sign-in-sessions",
            "Force password reset from a trusted admin account",
            "Review and remove attacker-added MFA methods or registered devices",
        ],
        "password_reset_then_mfa_registered": [
            "Audit who initiated the password reset and whether it was authorised",
            "Remove attacker-registered authenticator app or phone number",
            "Enable Conditional Access policy requiring compliant devices",
        ],
        "privilege_escalation_after_signin": [
            "Remove the unauthorised role assignment immediately",
            "Review all actions taken by the account while the role was held",
            "Enable Privileged Identity Management (PIM) for just-in-time role activation",
        ],
        "oauth_phishing_pattern": [
            "Revoke the OAuth consent grant: az ad app permission delete",
            "Block the offending application in the Entra portal (Enterprise Apps → disable)",
            "Enable admin consent requirements so users cannot self-consent to new apps",
        ],
        "bec_attack_pattern": [
            "Delete suspicious inbox rules immediately",
            "Remove external SMTP forwarding from mailbox settings",
            "Check sent items and deleted items for evidence of fraudulent communications",
            "Notify finance/HR if the attack window overlaps with financial transactions",
        ],
        "device_code_then_device_registered": [
            "Remove the attacker-registered device from Entra ID",
            "Revoke refresh tokens — device code tokens are long-lived",
            "Enable Conditional Access policy blocking device code flow where not required",
        ],
        "password_spray": [
            "Block the source IP in Conditional Access Named Locations",
            "Enable Entra ID Smart Lockout if not already configured",
            "Reset passwords for all accounts targeted in the spray window",
        ],
        "mass_mail_access": [
            "Determine which OAuth app or session accessed the mail — revoke it",
            "Review MailItemsAccessed audit log records for exfiltrated content",
            "Assess whether any sensitive data requires breach notification",
        ],
        "new_account_with_signin": [
            "Disable or delete the backdoor account immediately",
            "Audit what the account accessed during its active window",
            "Review app registrations and OAuth grants created by the account",
        ],
        "cross_ip_correlation": [
            "Pivot on the shared IP in both sign-in and audit logs for full activity timeline",
            "Block the IP in Conditional Access if it is confirmed malicious",
        ],
        "hosting_provider_signin": [
            "Investigate whether the cloud/proxy IP is a known attacker infrastructure",
            "Require compliant or hybrid-joined devices via Conditional Access",
        ],
    }

    # Group findings by severity
    sev_order = {"high": 0, "medium": 1, "low": 2}
    sorted_findings = sorted(findings, key=lambda f: sev_order.get(f.get("severity", "low"), 2))

    sev_color = {"high": "#ef4444", "medium": "#f97316", "low": "#6b7280"}
    sev_bg    = {"high": "#fef2f2", "medium": "#fff7ed", "low": "#f8fafc"}

    sections: list[str] = []
    item_index = 0  # for unique checkbox ids

    for f in sorted_findings:
        sev = f.get("severity", "low")
        color = sev_color.get(sev, "#6b7280")
        bg = sev_bg.get(sev, "#f8fafc")
        rule = f.get("rule", "")
        user = f.get("user") or "—"
        title = f.get("title") or rule
        recommendation = f.get("recommendation") or ""
        extra_actions = _RULE_ACTIONS.get(rule, [])

        # Build checklist items: recommendation first, then rule extras
        all_actions: list[str] = []
        if recommendation:
            all_actions.append(recommendation)
        all_actions.extend(extra_actions)

        items_html: list[str] = []
        for action in all_actions:
            item_index += 1
            cid = f"chk_{item_index}"
            items_html.append(
                f'<div style="display:flex;align-items:flex-start;gap:10px;'
                f'margin-bottom:8px">'
                f'<input type="checkbox" id="{cid}" style="margin-top:3px;'
                f'accent-color:{color};width:15px;height:15px;flex-shrink:0">'
                f'<label for="{cid}" style="cursor:pointer;font-size:13px;'
                f'line-height:1.5">{_e(action)}</label>'
                f'</div>'
            )

        mitre = f.get("mitre_techniques") or []
        mitre_badges = ""
        if mitre:
            mitre_badges = (
                '<div style="margin-top:8px">'
                '<span style="font-size:11px;color:var(--muted);font-weight:600">'
                'MITRE ATT&amp;CK&nbsp;</span>'
                + " ".join(
                    f'<span class="flag-badge" style="background:#eff6ff;color:#1d4ed8;'
                    f'border:1px solid #bfdbfe">{_e(t)}</span>'
                    for t in mitre
                )
                + '</div>'
            )

        sections.append(
            f'<div style="border:1px solid {color}40;border-radius:8px;'
            f'margin-bottom:18px;background:{bg};overflow:hidden">'
            f'<div style="background:{color}15;border-bottom:1px solid {color}30;'
            f'padding:10px 16px;display:flex;align-items:center;gap:12px">'
            f'<span style="background:{color};color:#fff;font-size:11px;font-weight:700;'
            f'padding:2px 8px;border-radius:4px;letter-spacing:.5px">'
            f'{_e(sev.upper())}</span>'
            f'<span style="font-weight:600;font-size:14px">{_e(title)}</span>'
            f'<span style="font-size:12px;color:var(--muted);margin-left:auto">'
            f'Account: {_e(user)}</span>'
            f'</div>'
            f'<div style="padding:14px 18px">'
            f'{"".join(items_html)}'
            f'{mitre_badges}'
            f'</div>'
            f'</div>'
        )

    total = len(findings)
    high_n = sum(1 for f in findings if f.get("severity") == "high")
    med_n  = sum(1 for f in findings if f.get("severity") == "medium")

    return (
        f'<div class="tab-content" id="remediation">'
        f'<div class="section-title">Remediation Checklist</div>'
        f'<p style="font-size:13px;color:var(--muted);margin-bottom:20px">'
        f'{total} finding(s) — <span style="color:#ef4444;font-weight:600">'
        f'{high_n} HIGH</span> &nbsp; '
        f'<span style="color:#f97316;font-weight:600">{med_n} MEDIUM</span>'
        f'&nbsp;·&nbsp; Tick each item as you complete it.</p>'
        f'{"".join(sections)}'
        f'</div>'
    )


def _html_domain_tab(domain_enrichment: dict) -> str:
    """Render the domain enrichment tab in the HTML report."""
    domains_dict: dict[str, dict] = domain_enrichment.get("domains") or {}
    total = domain_enrichment.get("total_domains", 0)
    suspicious = domain_enrichment.get("suspicious_count", 0)

    if not domains_dict:
        return (
            '<div class="tab-content" id="domain_enrichment">'
            '<div class="section-title">Domain Enrichment</div>'
            '<p class="no-data">No external domains found in case files.</p>'
            '</div>'
        )

    rows: list[str] = []
    for domain in sorted(domains_dict.keys()):
        data = domains_dict[domain]
        tags = data.get("threat_summary") or []
        is_susp = bool(tags)
        age_days = data.get("age_days")

        if age_days is None:
            age_str = "—"
            age_style = ""
        elif age_days < 30:
            age_str = f"{age_days}d"
            age_style = "color:#ef4444;font-weight:600"
        elif age_days < 90:
            age_str = f"{age_days}d"
            age_style = "color:#f97316;font-weight:600"
        else:
            age_str = f"{age_days}d"
            age_style = ""

        mx = data.get("mx_records") or []
        mx_str = _e(mx[0][:36]) if mx else '<span style="color:var(--muted)">no MX</span>'
        if data.get("routes_to_consumer_mail") and mx:
            mx_str = f'<span style="color:#f97316;font-weight:600">{_e(mx[0][:36])}</span>'

        spf = data.get("has_spf")
        dmarc = data.get("has_dmarc")
        spf_html = ('<span style="color:#22c55e">✓</span>' if spf else
                    '<span style="color:#ef4444">✗</span>' if spf is False else "—")
        dmarc_html = ('<span style="color:#22c55e">✓</span>' if dmarc else
                      '<span style="color:#ef4444">✗</span>' if dmarc is False else "—")

        if tags:
            tags_html = " ".join(
                f'<span class="flag-badge" style="background:#ef444420;color:#ef4444;border:1px solid #ef444440">'
                f'{_e(t)}</span>'
                for t in tags
            )
        else:
            tags_html = '<span style="color:var(--muted);font-size:11px">clean</span>'

        row_class = "flagged-row" if is_susp else ""
        rows.append(
            f'<tr class="{row_class}">'
            f'<td style="font-family:monospace">{_e(domain)}</td>'
            f'<td style="{age_style};text-align:right">{age_str}</td>'
            f'<td>{_e((data.get("registrar") or "—")[:28])}</td>'
            f'<td>{mx_str}</td>'
            f'<td style="text-align:center">{spf_html}</td>'
            f'<td style="text-align:center">{dmarc_html}</td>'
            f'<td class="flags-cell">{tags_html}</td>'
            f'</tr>'
        )

    return (
        f'<div class="tab-content" id="domain_enrichment">'
        f'<div class="section-title">Domain Enrichment — {total} domain(s), {suspicious} suspicious</div>'
        f'<table class="data-table">'
        f'<thead><tr><th>Domain</th><th>Age</th><th>Registrar</th>'
        f'<th>MX (first)</th><th>SPF</th><th>DMARC</th><th>Threat Tags</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody>'
        f'</table>'
        f'<p style="font-size:12px;color:var(--muted);margin-top:8px">'
        f'Age = days since domain registration via RDAP. '
        f'Consumer MX = mail routes to Gmail/Outlook/ProtonMail etc. '
        f'Run <code>cirrus enrich-domains</code> to refresh.</p>'
        f'</div>'
    )


def _html_enrichment_tab(enrichment: dict) -> str:
    ips_dict: dict[str, dict] = enrichment.get("ips") or {}
    total = enrichment.get("total_ips", 0)
    suspicious = enrichment.get("suspicious_count", 0)
    abuseipdb_used = enrichment.get("abuseipdb_used", False)

    if not ips_dict:
        return (
            '<div class="tab-content" id="ip_enrichment">'
            '<div class="section-title">IP Enrichment</div>'
            '<p class="no-data">No IP enrichment data found.</p>'
            '</div>'
        )

    vt_used = enrichment.get("vt_used", False)
    abuse_col = "<th>Abuse%</th>" if abuseipdb_used else ""
    vt_col = "<th>VT Malicious</th>" if vt_used else ""
    rows: list[str] = []
    for ip in sorted(ips_dict.keys()):
        data = ips_dict[ip]
        threat_tags = data.get("threat_summary") or []
        is_susp = bool(threat_tags)

        country = _e(data.get("country_code") or "—")
        city = _e((data.get("city") or "—")[:24])
        asn = _e(data.get("asn") or "")
        org = _e((data.get("org") or data.get("isp") or "")[:40])
        asn_org = f"{asn} {org}".strip() if asn else org

        if threat_tags:
            tags_html = " ".join(
                f'<span class="flag-badge" style="background:#ef444420;color:#ef4444;border:1px solid #ef444440">'
                f'{_e(t)}</span>'
                for t in threat_tags
            )
        else:
            tags_html = '<span style="color:var(--muted);font-size:11px">none</span>'

        ip_style = "color:#ef4444;font-weight:600" if is_susp else ""
        row_class = "flagged-row" if is_susp else ""

        abuse_cell = ""
        if abuseipdb_used:
            score = data.get("abuse_score")
            if score is None:
                abuse_cell = "<td>—</td>"
            elif int(score) >= 25:
                abuse_cell = f'<td style="color:#ef4444;font-weight:600">{_e(score)}</td>'
            else:
                abuse_cell = f"<td>{_e(score)}</td>"

        vt_cell = ""
        if vt_used:
            vt_mal = data.get("vt_malicious")
            if vt_mal is None:
                vt_cell = "<td>—</td>"
            elif int(vt_mal) > 0:
                vt_susp = data.get("vt_suspicious") or 0
                vt_cell = f'<td style="color:#ef4444;font-weight:600">{_e(vt_mal)} ({_e(vt_susp)}⚠)</td>'
            else:
                vt_cell = f"<td>0</td>"

        rows.append(
            f'<tr class="{row_class}">'
            f'<td style="font-family:monospace;{ip_style}">{_e(ip)}</td>'
            f'<td>{country}</td>'
            f'<td>{city}</td>'
            f'<td style="font-family:monospace;font-size:11px" title="{asn_org}">{asn_org[:44]}</td>'
            f'<td class="flags-cell">{tags_html}</td>'
            f'{abuse_cell}'
            f'{vt_cell}'
            f'</tr>'
        )

    abuseipdb_note = (
        '<p style="font-size:12px;color:var(--muted);margin-top:8px">'
        'AbuseIPDB data included. Abuse% = confidence score (0–100) that the IP is malicious. '
        'Scores ≥ 25 are highlighted.</p>'
        if abuseipdb_used else
        '<p style="font-size:12px;color:var(--muted);margin-top:8px">'
        'AbuseIPDB enrichment not run. Re-run '
        '<code>cirrus enrich --abuseipdb-key &lt;key&gt;</code> to add abuse scores. '
        'Register free at <a href="https://www.abuseipdb.com/register" target="_blank">'
        'abuseipdb.com/register</a>.</p>'
    )

    return (
        f'<div class="tab-content" id="ip_enrichment">'
        f'<div class="section-title">IP Enrichment — {total} address(es), {suspicious} suspicious</div>'
        f'<table class="data-table">'
        f'<thead><tr><th>IP Address</th><th>Country</th><th>City</th>'
        f'<th>ASN / Org</th><th>Threat Tags</th>{abuse_col}{vt_col}</tr></thead>'
        f'<tbody>{"".join(rows)}</tbody>'
        f'</table>'
        f'{abuseipdb_note}'
        f'</div>'
    )


# ── Main entry point ───────────────────────────────────────────────────────────

def generate_report(case_dir: Path) -> Path:
    """
    Generate investigation_report.html in the case directory.
    Returns the path to the written file.
    """
    meta = _read_case_meta(case_dir)
    meta["generated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    data = _load_data(case_dir)
    corr = _load_correlation(case_dir)
    enrichment = _load_enrichment(case_dir)
    domain_enrichment = _load_domain_enrichment(case_dir)
    stats = _build_stats(data)
    timeline = _build_timeline(data)
    user_summary = _build_user_summary(data)

    # Tab content: correlation, timeline, users, optional remediation, optional enrichment,
    # optional domain enrichment, then one tab per collector
    tab_contents: list[str] = [
        _html_correlation_tab(corr),
        _html_timeline_tab(timeline),
        _html_users_tab(user_summary),
    ]
    if corr.get("findings"):
        tab_contents.append(_html_remediation_tab(corr))
    if enrichment and enrichment.get("total_ips", 0) > 0:
        tab_contents.append(_html_enrichment_tab(enrichment))
    if domain_enrichment and domain_enrichment.get("total_domains", 0) > 0:
        tab_contents.append(_html_domain_tab(domain_enrichment))
    for key, records in data.items():
        if records:
            tab_contents.append(_html_collector_tab(key, records))

    html_parts = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        f'<meta charset="utf-8">',
        f'<meta name="viewport" content="width=device-width,initial-scale=1">',
        f'<title>CIRRUS Report — {_e(meta["case_name"])}</title>',
        _html_css(),
        "</head>",
        "<body>",
        _html_header(meta, stats, corr),
        _html_tab_nav(data, corr, timeline, enrichment, domain_enrichment),
        *tab_contents,
        f'<div class="report-footer">Generated by CIRRUS &nbsp;·&nbsp; {_e(meta["generated_at"])}'
        f' &nbsp;·&nbsp; Case: {_e(meta["case_name"])}</div>',
        _html_js(),
        "</body></html>",
    ]

    output_path = case_dir / "investigation_report.html"
    output_path.write_text("\n".join(html_parts), encoding="utf-8")
    return output_path
