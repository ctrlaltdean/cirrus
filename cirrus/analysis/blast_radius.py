"""
Blast Radius Assessment

Maps the potential impact of a compromised account by querying Microsoft Graph
for all access dimensions associated with a user: group memberships, app role
assignments, owned objects, recent sign-in applications, and OAuth grants.

Each dimension is checked in parallel and assigned one of four status levels:
  clean    — no elevated access found
  warn     — moderate access (member of groups, standard app roles)
  high     — high-privilege access (admin roles, sensitive app permissions)
  error    — API call failed or insufficient permissions

The overall risk level is the highest status across all dimensions.

Usage:
    from cirrus.analysis.blast_radius import run_blast_radius
    report = run_blast_radius(token, upn, tenant, case_dir)

Or via CLI:
    cirrus blast-radius --tenant contoso.com --user john@contoso.com
"""

from __future__ import annotations

from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable

import requests

GRAPH_BASE = "https://graph.microsoft.com/v1.0"

# ── High-privilege indicators ──────────────────────────────────────────────────

_HIGH_PRIV_ROLES = frozenset({
    "global administrator",
    "privileged role administrator",
    "security administrator",
    "exchange administrator",
    "privileged authentication administrator",
    "authentication administrator",
    "user administrator",
    "application administrator",
    "cloud application administrator",
    "conditional access administrator",
    "intune administrator",
    "teams administrator",
    "sharepoint administrator",
    "compliance administrator",
    "billing administrator",
})

_HIGH_PRIV_GROUPS = frozenset({
    "global admins", "global administrators",
    "company administrators", "privileged identity management",
    "security operators", "security readers",
    "exchange admins", "exchange administrators",
})

_HIGH_IMPACT_APP_ROLE_KEYWORDS = frozenset({
    "readwrite.all", "read.all", "full_access", "manage",
    "directory.readwrite", "rolemanagement", "user.readwrite.all",
    "mail.readwrite", "files.readwrite.all",
})

_SENSITIVE_APPS = frozenset({
    # Microsoft first-party apps that indicate broad delegated access
    "00000002-0000-0ff1-ce00-000000000000",  # Office 365 Exchange Online
    "00000003-0000-0000-c000-000000000000",  # Microsoft Graph
    "00000007-0000-0000-c000-000000000000",  # Common Data Service
})

_STATUS_RANK = {"high": 3, "warn": 2, "clean": 1, "skipped": 0, "error": 0}


# ── Result dataclasses ─────────────────────────────────────────────────────────

@dataclass
class AccessDimension:
    label: str
    status: str                           # clean | warn | high | error | skipped
    summary: str
    detail: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    item_count: int = 0


@dataclass
class BlastRadiusReport:
    user: str
    tenant: str
    dimensions: list[AccessDimension] = field(default_factory=list)

    @property
    def risk_level(self) -> str:
        if any(d.status == "high" for d in self.dimensions):
            return "high"
        if any(d.status == "warn" for d in self.dimensions):
            return "warn"
        return "clean"

    @property
    def high_privilege_summary(self) -> list[str]:
        """Return all HIGH-severity flags across all dimensions."""
        flags: list[str] = []
        for d in self.dimensions:
            flags.extend(f for f in d.flags if f.startswith("HIGH_"))
        return list(dict.fromkeys(flags))

    @property
    def flagged_count(self) -> int:
        return sum(1 for d in self.dimensions if d.status in ("high", "warn"))


# ── API helpers ────────────────────────────────────────────────────────────────

def _get(session: requests.Session, url: str, params: dict | None = None) -> dict | list:
    resp = session.get(url, params=params, timeout=30)
    if resp.status_code == 403:
        raise PermissionError(f"403 Forbidden: {url}")
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
        if isinstance(data, dict):
            results.extend(data.get("value") or [])
            next_url = data.get("@odata.nextLink")
        else:
            break
    return results


def _resolve_upn_to_id(session: requests.Session, upn: str) -> str:
    """Resolve a UPN to an object ID for use in Graph API calls."""
    data = _get(session, f"{GRAPH_BASE}/users/{upn}", params={"$select": "id"})
    if isinstance(data, dict):
        return data.get("id") or upn
    return upn


# ── Individual dimension checks ────────────────────────────────────────────────

def _check_group_memberships(session: requests.Session, upn: str) -> AccessDimension:
    label = "Group memberships"
    try:
        groups = _collect_all(
            session,
            f"{GRAPH_BASE}/users/{upn}/memberOf",
            params={"$select": "id,displayName,groupTypes,isAssignableToRole", "$top": "999"},
        )
    except PermissionError:
        return AccessDimension(label, "skipped", "Requires Directory.Read.All")
    except Exception as exc:
        return AccessDimension(label, "error", str(exc)[:120])

    if not groups:
        return AccessDimension(label, "clean", "No group memberships", item_count=0)

    flags: list[str] = []
    detail: list[str] = []
    high_count = 0

    for g in groups:
        name = g.get("displayName") or ""
        assignable = g.get("isAssignableToRole") or False

        if name.lower() in _HIGH_PRIV_GROUPS:
            flags.append(f"HIGH_PRIV_GROUP:{name}")
            detail.append(f"[HIGH] {name} — privileged group")
            high_count += 1
        elif assignable:
            flags.append(f"HIGH_ROLE_ASSIGNABLE_GROUP:{name}")
            detail.append(f"[HIGH] {name} — role-assignable group")
            high_count += 1
        else:
            detail.append(name)

    flags = list(dict.fromkeys(flags))
    status = "high" if high_count else ("warn" if len(groups) > 5 else "clean")

    summary = f"{len(groups)} group(s)"
    if high_count:
        summary += f" — {high_count} HIGH-PRIVILEGE"

    return AccessDimension(label, status, summary, detail[:10], flags, item_count=len(groups))


def _check_directory_roles(session: requests.Session, upn: str) -> AccessDimension:
    label = "Directory roles"
    try:
        roles = _collect_all(
            session,
            f"{GRAPH_BASE}/users/{upn}/transitiveMemberOf/microsoft.graph.directoryRole",
            params={"$select": "id,displayName,description", "$top": "999"},
        )
    except PermissionError:
        return AccessDimension(label, "skipped", "Requires Directory.Read.All")
    except (FileNotFoundError, ValueError):
        # Fallback: some tenants need different endpoint
        try:
            roles = _collect_all(
                session,
                f"{GRAPH_BASE}/users/{upn}/memberOf/microsoft.graph.directoryRole",
                params={"$select": "id,displayName", "$top": "999"},
            )
        except Exception as exc2:
            return AccessDimension(label, "error", str(exc2)[:120])
    except Exception as exc:
        return AccessDimension(label, "error", str(exc)[:120])

    if not roles:
        return AccessDimension(label, "clean", "No directory roles assigned", item_count=0)

    flags: list[str] = []
    detail: list[str] = []
    high_count = 0

    for r in roles:
        name = r.get("displayName") or ""
        if name.lower() in _HIGH_PRIV_ROLES:
            flags.append(f"HIGH_PRIV_ROLE:{name}")
            detail.append(f"[HIGH] {name}")
            high_count += 1
        else:
            flags.append(f"ROLE:{name}")
            detail.append(name)

    flags = list(dict.fromkeys(flags))
    status = "high" if high_count else "warn"

    summary = f"{len(roles)} role(s)"
    if high_count:
        summary += f" — {high_count} HIGH-PRIVILEGE"

    return AccessDimension(label, status, summary, detail[:10], flags, item_count=len(roles))


def _check_app_role_assignments(session: requests.Session, upn: str) -> AccessDimension:
    label = "App role assignments"
    try:
        assignments = _collect_all(
            session,
            f"{GRAPH_BASE}/users/{upn}/appRoleAssignments",
            params={"$top": "999"},
        )
    except PermissionError:
        return AccessDimension(label, "skipped", "Requires Directory.Read.All")
    except Exception as exc:
        return AccessDimension(label, "error", str(exc)[:120])

    if not assignments:
        return AccessDimension(label, "clean", "No app role assignments", item_count=0)

    flags: list[str] = []
    detail: list[str] = []
    high_count = 0

    for a in assignments:
        app_name = a.get("principalDisplayName") or a.get("resourceDisplayName") or ""
        resource = a.get("resourceDisplayName") or ""
        role_id = a.get("appRoleId") or ""

        # Check if the resource app is a known sensitive app
        resource_id = a.get("resourceId") or ""
        is_sensitive = resource_id in _SENSITIVE_APPS

        # App roles that look high-impact by keyword
        role_display = a.get("displayName") or role_id
        is_high_impact = any(
            kw in (role_display or "").lower()
            for kw in _HIGH_IMPACT_APP_ROLE_KEYWORDS
        )

        if is_sensitive or is_high_impact:
            flags.append(f"HIGH_APP_ROLE:{resource}:{role_display[:30]}")
            detail.append(f"[HIGH] {resource} — {role_display[:40]}")
            high_count += 1
        else:
            detail.append(f"{resource} — {role_display[:40]}")

    flags = list(dict.fromkeys(flags))
    status = "high" if high_count else "warn"

    summary = f"{len(assignments)} app role(s)"
    if high_count:
        summary += f" — {high_count} high-impact"

    return AccessDimension(label, status, summary, detail[:10], flags, item_count=len(assignments))


def _check_owned_objects(session: requests.Session, upn: str) -> AccessDimension:
    label = "Owned objects"
    try:
        objects = _collect_all(
            session,
            f"{GRAPH_BASE}/users/{upn}/ownedObjects",
            params={"$select": "id,displayName,@odata.type", "$top": "999"},
        )
    except PermissionError:
        return AccessDimension(label, "skipped", "Requires Directory.Read.All")
    except Exception as exc:
        return AccessDimension(label, "error", str(exc)[:120])

    if not objects:
        return AccessDimension(label, "clean", "No owned objects", item_count=0)

    type_counts: dict[str, int] = defaultdict(int)
    detail: list[str] = []
    flags: list[str] = []

    for obj in objects:
        odata_type = (obj.get("@odata.type") or "").split(".")[-1]
        name = obj.get("displayName") or obj.get("id", "")
        type_counts[odata_type] += 1

        # App registrations owned by this user are high-impact — an attacker
        # with this access can add credentials to those apps
        if odata_type in ("application", "servicePrincipal"):
            flags.append(f"OWNS_APP_REGISTRATION:{name[:40]}")
            detail.append(f"[HIGH] App registration: {name}")
        else:
            detail.append(f"{odata_type}: {name}")

    flags = list(dict.fromkeys(flags))
    high_count = sum(1 for f in flags if f.startswith("OWNS_APP_REGISTRATION:"))
    status = "high" if high_count else ("warn" if len(objects) > 3 else "clean")

    type_summary = ", ".join(f"{v}× {k}" for k, v in type_counts.items())
    summary = f"{len(objects)} object(s): {type_summary}"

    return AccessDimension(label, status, summary, detail[:10], flags, item_count=len(objects))


def _check_oauth_grants(session: requests.Session, upn: str) -> AccessDimension:
    label = "OAuth grants (delegated)"
    _HIGH_RISK_SCOPES = frozenset({
        "Mail.Read", "Mail.ReadWrite", "Mail.Send", "MailboxSettings.ReadWrite",
        "full_access_as_user", "Files.Read.All", "Files.ReadWrite.All",
        "Directory.Read.All", "Directory.ReadWrite.All", "User.Read.All",
        "User.ReadWrite.All", "RoleManagement.ReadWrite.Directory",
    })

    try:
        grants = _collect_all(
            session,
            f"{GRAPH_BASE}/users/{upn}/oauth2PermissionGrants",
            params={"$top": "999"},
        )
    except PermissionError:
        return AccessDimension(label, "skipped", "Requires Directory.Read.All")
    except Exception as exc:
        return AccessDimension(label, "error", str(exc)[:120])

    if not grants:
        return AccessDimension(label, "clean", "No OAuth grants", item_count=0)

    flags: list[str] = []
    detail: list[str] = []
    high_count = 0

    for grant in grants:
        scope_str = grant.get("scope") or ""
        client_id = grant.get("clientId") or ""
        high_scopes = [s for s in scope_str.split() if s.strip() in _HIGH_RISK_SCOPES]
        if high_scopes:
            flags.append(f"HIGH_RISK_SCOPE:{','.join(high_scopes[:4])}")
            detail.append(f"[HIGH] App {client_id[:16]}… — scopes: {', '.join(high_scopes[:3])}")
            high_count += 1
        else:
            scope_preview = scope_str[:60]
            detail.append(f"App {client_id[:16]}… — {scope_preview}")

    flags = list(dict.fromkeys(flags))
    status = "high" if high_count else "warn"

    summary = f"{len(grants)} grant(s)"
    if high_count:
        summary += f" — {high_count} with high-risk scopes"

    return AccessDimension(label, status, summary, detail[:10], flags, item_count=len(grants))


def _check_signin_apps(session: requests.Session, upn: str) -> AccessDimension:
    """Recent apps used to sign in — indicates what services are accessible."""
    label = "Recent sign-in apps"
    try:
        records = _collect_all(
            session,
            f"{GRAPH_BASE}/auditLogs/signIns",
            params={
                "$filter": f"userPrincipalName eq '{upn}'",
                "$top": "100",
                "$select": "appDisplayName,appId,createdDateTime,status",
                "$orderby": "createdDateTime desc",
            },
        )
    except PermissionError:
        return AccessDimension(label, "skipped", "Requires AuditLog.Read.All / Entra ID P1")
    except Exception as exc:
        return AccessDimension(label, "error", str(exc)[:120])

    if not records:
        return AccessDimension(label, "clean", "No recent sign-in activity", item_count=0)

    # Unique successful app sign-ins
    apps_seen: dict[str, str] = {}  # appId -> appDisplayName
    for r in records:
        status = r.get("status") or {}
        if (status.get("errorCode") or 0) == 0:
            app_id = r.get("appId") or ""
            app_name = r.get("appDisplayName") or app_id
            if app_id and app_id not in apps_seen:
                apps_seen[app_id] = app_name

    detail = [f"{name} ({aid[:8]}…)" for aid, name in list(apps_seen.items())[:10]]
    status = "warn" if len(apps_seen) > 5 else "clean"

    summary = (
        f"{len(records)} sign-in event(s) · "
        f"{len(apps_seen)} distinct app(s): "
        f"{', '.join(list(apps_seen.values())[:3])}"
        + (f", +{len(apps_seen)-3} more" if len(apps_seen) > 3 else "")
    )

    return AccessDimension(label, status, summary, detail, [], item_count=len(apps_seen))


# ── Ordered checks ─────────────────────────────────────────────────────────────

_CHECKS = [
    ("directory_roles",        _check_directory_roles),
    ("group_memberships",      _check_group_memberships),
    ("app_role_assignments",   _check_app_role_assignments),
    ("owned_objects",          _check_owned_objects),
    ("oauth_grants",           _check_oauth_grants),
    ("signin_apps",            _check_signin_apps),
]


# ── Runner ─────────────────────────────────────────────────────────────────────

def run_blast_radius(
    token: str,
    upn: str,
    tenant: str = "",
    case_dir=None,
    on_progress: Callable[[str], None] | None = None,
) -> BlastRadiusReport:
    """
    Run all blast-radius checks for a single user in parallel.

    Args:
        token:       Bearer token with Directory.Read.All + AuditLog.Read.All.
        upn:         User Principal Name of the account being assessed.
        tenant:      Tenant domain (informational only).
        case_dir:    If provided, writes blast_radius.json to this directory.
        on_progress: Optional callback for progress messages.

    Returns:
        BlastRadiusReport with one AccessDimension per check.
    """
    import json
    from dataclasses import asdict
    from pathlib import Path

    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "ConsistencyLevel": "eventual",
    })

    report = BlastRadiusReport(user=upn, tenant=tenant)
    results_map: dict[str, AccessDimension] = {}

    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = {
            pool.submit(fn, session, upn): key
            for key, fn in _CHECKS
        }
        for future in as_completed(futures):
            key = futures[future]
            try:
                results_map[key] = future.result()
            except Exception as exc:
                results_map[key] = AccessDimension(key, "error", str(exc)[:120])

    # Restore canonical order
    report.dimensions = [results_map[key] for key, _ in _CHECKS if key in results_map]

    # Optionally persist to case directory
    if case_dir is not None:
        path = Path(case_dir) / "blast_radius.json"
        output = {
            "user":       upn,
            "tenant":     tenant,
            "risk_level": report.risk_level,
            "high_privilege_summary": report.high_privilege_summary,
            "dimensions": [
                {
                    "label":      d.label,
                    "status":     d.status,
                    "summary":    d.summary,
                    "detail":     d.detail,
                    "flags":      d.flags,
                    "item_count": d.item_count,
                }
                for d in report.dimensions
            ],
        }
        path.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")

    return report
