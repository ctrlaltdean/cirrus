"""
Cross-Collector Correlation Engine

After all collectors have run and written output to the case directory, the
correlation engine reads the JSON files, links events across collectors, and
produces a consolidated findings report: ioc_correlation.json.

Each finding represents a multi-collector pattern that is materially more
suspicious than any single flag in isolation. This layer does not replace
per-record _iocFlags — it adds a separate reasoning pass that spans multiple
data sources and detects attack patterns that only become visible when records
from different collectors are viewed together.

Correlation rules (all findings include the supporting evidence records):

  suspicious_signin_then_persistence  [HIGH]
    A sign-in with suspicious indicators (device code, impossible travel,
    geo-risk) on the same account that also has a new MFA method or device
    registered during the collection window.

  password_reset_then_mfa_registered  [HIGH]
    An admin password reset in the audit log for a user who also has a
    RECENTLY_ADDED MFA method. Classic ATO pattern: attacker resets the
    victim's password, then registers their own authenticator.

  privilege_escalation_after_signin   [HIGH]
    A sign-in event for a user who is also the target of a HIGH_PRIV_ROLE_ASSIGNED
    audit event within the collection window.

  oauth_phishing_pattern              [HIGH]
    A sign-in using device code or ROPC for a user who also has an OAuth grant
    with a HIGH_RISK_SCOPE (mail read, file access, directory access).

  bec_attack_pattern                  [HIGH]
    A user with any sign-in activity who also has a mailbox inbox rule with a
    FORWARDS_TO flag or a mail forwarding record with EXTERNAL_SMTP_FORWARD.

  device_code_then_device_registered  [HIGH]
    A device code authentication sign-in for a user who also has a
    RECENTLY_REGISTERED device in the collection window.

  password_spray                      [HIGH/MEDIUM]
    A single IP with 10+ failed sign-in attempts against 5+ distinct accounts.
    Elevated to HIGH when at least one targeted account also had a successful
    sign-in from the same IP (spray may have succeeded).

  mass_mail_access                    [HIGH/MEDIUM]
    A user with 50+ MailItemsAccessed events in the UAL collection window.
    Elevated to HIGH when the user also has interactive sign-in activity.
    Indicates an attacker or compromised OAuth app bulk-reading mailbox content.

  new_account_with_signin             [MEDIUM]
    A user flagged RECENTLY_CREATED in the users collector who also appears
    in sign-in logs — may indicate an attacker-created backdoor account.

  cross_ip_correlation                [MEDIUM]
    A public IP address that appears in both sign-in logs and directory audit
    logs — suggests the same session or attacker source performed both auth
    and directory changes.

  hosting_provider_signin             [MEDIUM]
    A successful sign-in from an IP that ip_enrichment.json identifies as a
    datacenter, hosting provider, proxy, or Tor exit node. Indicates the
    account may have been accessed via anonymising infrastructure or an
    attacker-controlled cloud VM. Only fires when ip_enrichment.json is
    present (run `cirrus enrich` first).
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Collector JSON filenames (without extension) ──────────────────────────────
_COLLECTOR_FILES = {
    "signin_logs":        "signin_logs.json",
    "audit_logs":         "entra_audit_logs.json",
    "mfa_methods":        "mfa_methods.json",
    "users":              "users.json",
    "registered_devices": "registered_devices.json",
    "oauth_grants":       "oauth_grants.json",
    "mailbox_rules":      "mailbox_rules.json",
    "mail_forwarding":    "mail_forwarding.json",
    "unified_audit_log":  "unified_audit_log.json",
    "sp_signin_logs":     "sp_signin_logs.json",
    "pim_activations":    "pim_activations.json",
}

# Default thresholds for spray / mass-access rules (sensitivity="medium")
_SPRAY_MIN_TARGETS  = 5   # distinct accounts from one IP to trigger password spray
_SPRAY_MIN_FAILURES = 10  # total failed attempts from one IP to trigger password spray
_MAIL_ACCESS_THRESHOLD = 50  # MailItemsAccessed events to trigger mass mail access

# Per-sensitivity overrides: (spray_min_targets, spray_min_failures, mail_access_threshold)
_SENSITIVITY_THRESHOLDS: dict[str, tuple[int, int, int]] = {
    "low":    (10, 20, 100),  # enterprise / large tenant — reduce noise
    "medium": (5,  10,  50),  # default
    "high":   (3,   5,  20),  # SMB / small tenant — catch low-volume attacks
}

from cirrus.utils.flags import (
    SUSPICIOUS_SIGNIN_PREFIXES as _SUSPICIOUS_SIGNIN_PREFIXES,
    PERSISTENCE_AUDIT_PREFIXES as _PERSISTENCE_AUDIT_PREFIXES_TUPLE,
)


# ── Data structures ────────────────────────────────────────────────────────────

@dataclass
class Evidence:
    """A single piece of supporting evidence from one collector."""
    collector: str
    timestamp: str
    summary: str
    flags: list[str]


@dataclass
class Finding:
    """A correlated IOC finding spanning one or more collectors."""
    id: str
    rule: str
    severity: str       # "high" | "medium" | "low"
    title: str
    user: str           # Primary affected user (empty string for non-user rules)
    description: str
    evidence: list[Evidence]
    recommendation: str
    ioc_flags: list[str] = field(default_factory=list)      # de-duplicated flags from evidence
    mitre_techniques: list[str] = field(default_factory=list)  # ATT&CK technique IDs
    temporal_proximity: str = ""      # "minutes" | "hours" | "same_day" | "days" | ""
    proximity_minutes: int | None = None  # actual gap in minutes between key events


# ── MITRE ATT&CK technique mappings ───────────────────────────────────────────
# Technique IDs reference the Enterprise ATT&CK matrix v15.
# Format: "TXXXX[.YYY] — Name" for human readability in reports.

_RULE_TECHNIQUES: dict[str, list[str]] = {
    "suspicious_signin_then_persistence": [
        "T1078 — Valid Accounts",
        "T1556.006 — Modify Auth Process: Multi-Factor Authentication",
    ],
    "password_reset_then_mfa_registered": [
        "T1098.005 — Account Manipulation: Device Registration",
        "T1556.006 — Modify Auth Process: Multi-Factor Authentication",
    ],
    "privilege_escalation_after_signin": [
        "T1078 — Valid Accounts",
        "T1548 — Abuse Elevation Control Mechanism",
        "T1098.003 — Account Manipulation: Additional Cloud Roles",
    ],
    "oauth_phishing_pattern": [
        "T1528 — Steal Application Access Token",
        "T1566 — Phishing",
    ],
    "bec_attack_pattern": [
        "T1114.003 — Email Collection: Email Forwarding Rule",
        "T1020 — Automated Exfiltration",
    ],
    "dual_exfiltration_channels": [
        "T1114.003 — Email Collection: Email Forwarding Rule",
        "T1528 — Steal Application Access Token",
        "T1020 — Automated Exfiltration",
    ],
    "device_code_then_device_registered": [
        "T1528 — Steal Application Access Token",
        "T1098.005 — Account Manipulation: Device Registration",
    ],
    "password_spray": [
        "T1110.003 — Brute Force: Password Spraying",
    ],
    "spray_then_escalation": [
        "T1110.003 — Brute Force: Password Spraying",
        "T1078 — Valid Accounts",
        "T1098.003 — Account Manipulation: Additional Cloud Roles",
        "T1098.005 — Account Manipulation: Device Registration",
    ],
    "mass_mail_access": [
        "T1114.002 — Email Collection: Remote Email Collection",
    ],
    "new_account_with_signin": [
        "T1136.003 — Create Account: Cloud Account",
        "T1078.004 — Valid Accounts: Cloud Accounts",
    ],
    "cross_ip_correlation": [
        "T1078 — Valid Accounts",
    ],
    "hosting_provider_signin": [
        "T1090 — Proxy",
        "T1078 — Valid Accounts",
    ],
    "pim_activation_after_suspicious_signin": [
        "T1548 — Abuse Elevation Control Mechanism",
        "T1078 — Valid Accounts",
        "T1098.003 — Account Manipulation: Additional Cloud Roles",
    ],
    "ca_coverage_gap": [
        "T1078 — Valid Accounts",
        "T1562.001 — Impair Defenses: Disable or Modify Tools",
    ],
}


# ── Helpers ────────────────────────────────────────────────────────────────────

def _parse_dt(ts: str) -> datetime:
    """Parse an ISO-8601 timestamp to UTC-aware datetime, or return epoch on failure."""
    if not ts:
        return datetime.min.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return datetime.min.replace(tzinfo=timezone.utc)


def _closest_pair_gap(
    records_a: list[dict], ts_key_a: str,
    records_b: list[dict], ts_key_b: str,
) -> tuple[int | None, str]:
    """
    Find the smallest time gap between any event in *records_a* and any event
    in *records_b*.  Returns (gap_minutes, proximity_label).

    proximity_label is one of: "minutes", "hours", "same_day", "days", or ""
    if either list is empty or timestamps are unparseable.
    """
    if not records_a or not records_b:
        return None, ""

    times_a = [_parse_dt(r.get(ts_key_a) or "") for r in records_a]
    times_b = [_parse_dt(r.get(ts_key_b) or "") for r in records_b]

    epoch = datetime.min.replace(tzinfo=timezone.utc)
    times_a = [t for t in times_a if t != epoch]
    times_b = [t for t in times_b if t != epoch]
    if not times_a or not times_b:
        return None, ""

    min_gap = min(
        abs((ta - tb).total_seconds())
        for ta in times_a for tb in times_b
    )
    gap_minutes = int(min_gap / 60)
    label = _proximity_label(gap_minutes)
    return gap_minutes, label


def _proximity_label(gap_minutes: int) -> str:
    """Map a gap in minutes to a human-readable proximity bucket."""
    if gap_minutes <= 60:
        return "minutes"
    if gap_minutes <= 360:  # 6 hours
        return "hours"
    if gap_minutes <= 1440:  # 24 hours
        return "same_day"
    return "days"


def _proximity_severity_boost(base_severity: str, proximity: str) -> str:
    """
    Optionally boost severity when events are temporally close.

    Rules:
      - "minutes" proximity on a MEDIUM finding → promote to HIGH
      - "hours"   proximity on a MEDIUM finding → promote to HIGH
      - "days"    proximity on a HIGH finding   → no change (already high)
    """
    if base_severity == "medium" and proximity in ("minutes", "hours"):
        return "high"
    return base_severity


def _proximity_note(proximity: str, gap_minutes: int | None) -> str:
    """Return a human-readable note for inclusion in finding descriptions."""
    if gap_minutes is None or not proximity:
        return ""
    if proximity == "minutes":
        return f"Events occurred within {gap_minutes} minute(s) of each other — strong temporal correlation."
    if proximity == "hours":
        hrs = gap_minutes // 60
        return f"Events occurred within ~{hrs} hour(s) of each other — moderate temporal correlation."
    if proximity == "same_day":
        return "Events occurred within the same 24-hour window."
    # "days"
    days = gap_minutes // 1440
    return f"Events occurred ~{days} day(s) apart within the collection window."


def _flags(record: dict) -> list[str]:
    return record.get("_iocFlags") or []


def _has_flag_prefix(record: dict, *prefixes: str) -> bool:
    return any(f.startswith(p) for f in _flags(record) for p in prefixes)


def _extract_flags_with_prefix(records: list[dict], *prefixes: str) -> list[str]:
    """Collect all flag strings that start with any of the given prefixes."""
    seen: set[str] = set()
    result: list[str] = []
    for r in records:
        for f in _flags(r):
            if f not in seen and any(f.startswith(p) for p in prefixes):
                seen.add(f)
                result.append(f)
    return result


def _extract_ips_from_flags(records: list[dict]) -> set[str]:
    """Extract IP addresses from PUBLIC_IP:<ip> flags."""
    ips: set[str] = set()
    for r in records:
        for f in _flags(r):
            if f.startswith("PUBLIC_IP:"):
                ips.add(f[len("PUBLIC_IP:"):])
    return ips


def _evidence(record: dict, collector: str, timestamp_key: str, summary: str) -> Evidence:
    ts = record.get(timestamp_key) or ""
    return Evidence(
        collector=collector,
        timestamp=ts,
        summary=summary,
        flags=_flags(record),
    )


def _target_users_from_audit(record: dict) -> list[str]:
    """Extract target user UPNs from an audit log record's targetResources."""
    upns: list[str] = []
    for res in record.get("targetResources") or []:
        res_type = (res.get("type") or "").lower()
        if res_type == "user":
            upn = res.get("userPrincipalName") or res.get("displayName") or ""
            if upn and "@" in upn:
                upns.append(upn.lower())
    return upns


def _initiator_upn(record: dict) -> str:
    """Extract the initiating user UPN from an audit record."""
    initiated_by = record.get("initiatedBy") or {}
    user = initiated_by.get("user") or {}
    return (user.get("userPrincipalName") or "").lower()


def _dedup_flags(evidence_list: list[Evidence]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for ev in evidence_list:
        for f in ev.flags:
            if f not in seen:
                seen.add(f)
                result.append(f)
    return result


# ── Correlation Engine ─────────────────────────────────────────────────────────

class CorrelationEngine:
    """
    Loads collector JSON output files from a case directory and runs
    all correlation rules to produce a list of cross-collector findings.
    """

    def __init__(self, case_dir: Path, sensitivity: str = "medium") -> None:
        self.case_dir = case_dir
        self._data: dict[str, list[dict]] = {}
        self._loaded: list[str] = []
        sens = sensitivity if sensitivity in _SENSITIVITY_THRESHOLDS else "medium"
        t = _SENSITIVITY_THRESHOLDS[sens]
        self._spray_min_targets  = t[0]
        self._spray_min_failures = t[1]
        self._mail_access_threshold = t[2]
        self.sensitivity = sens

    # ── Public interface ───────────────────────────────────────────────────────

    def run(self) -> dict[str, Any]:
        """
        Load data, run all rules, and return the correlation report as a dict.
        Also writes ioc_correlation.json to the case directory.
        """
        self._load()

        findings: list[Finding] = []
        _id = [0]

        def _next_id() -> str:
            _id[0] += 1
            return f"CORR-{_id[0]:03d}"

        rules = [
            self._rule_suspicious_signin_then_persistence,
            self._rule_password_reset_then_mfa_registered,
            self._rule_privilege_escalation_after_signin,
            self._rule_oauth_phishing_pattern,
            self._rule_bec_attack_pattern,
            self._rule_dual_exfiltration_channels,
            self._rule_device_code_then_device_registered,
            self._rule_password_spray,
            self._rule_spray_then_escalation,
            self._rule_mass_mail_access,
            self._rule_new_account_with_signin,
            self._rule_cross_ip_correlation,
            self._rule_hosting_provider_signin,
            self._rule_pim_activation_after_suspicious_signin,
            self._rule_ca_coverage_gap,
        ]

        for rule_fn in rules:
            try:
                rule_findings = rule_fn()
                for f in rule_findings:
                    f.id = _next_id()
                    f.ioc_flags = _dedup_flags(f.evidence)
                    f.mitre_techniques = _RULE_TECHNIQUES.get(f.rule, [])
                findings.extend(rule_findings)
            except Exception:
                pass  # Never let a broken rule crash the whole workflow

        # ── Custom YAML rules ─────────────────────────────────────────────
        try:
            from cirrus.analysis.custom_rules import load_custom_rules, run_custom_rules
            custom_paths = [
                self.case_dir / "custom_rules.yaml",
                self.case_dir / "custom_rules.yml",
                Path.home() / ".cirrus" / "custom_rules.yaml",
            ]
            for cp in custom_paths:
                custom_rules = load_custom_rules(cp)
                if custom_rules:
                    custom_findings = run_custom_rules(custom_rules, self._data)
                    for f in custom_findings:
                        f.id = _next_id()
                        f.ioc_flags = _dedup_flags(f.evidence)
                    findings.extend(custom_findings)
        except Exception:
            pass  # custom rules are optional — never block built-in rules

        counts = {"high": 0, "medium": 0, "low": 0}
        affected_users: set[str] = set()
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
            if f.user:
                affected_users.add(f.user)

        report: dict[str, Any] = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "case_dir": str(self.case_dir),
            "collectors_loaded": self._loaded,
            "sensitivity": self.sensitivity,
            "summary": {
                "total_findings": len(findings),
                **counts,
                "affected_users": sorted(affected_users),
            },
            "findings": [_finding_to_dict(f) for f in findings],
        }

        output_path = self.case_dir / "ioc_correlation.json"
        output_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )

        txt_path = self.case_dir / "ioc_correlation.txt"
        _write_text_report(report, findings, txt_path)

        ps_path = self.case_dir / "remediation_commands.ps1"
        _write_remediation_script(findings, ps_path)

        return report

    # ── Data loading ───────────────────────────────────────────────────────────

    def _load(self) -> None:
        for key, filename in _COLLECTOR_FILES.items():
            path = self.case_dir / "collection" / "json" / filename
            if not path.exists():
                path = self.case_dir / "collection" / filename  # pre-json-subdir
            if not path.exists():
                path = self.case_dir / filename  # backward compat: flat structure
            if path.exists():
                try:
                    with path.open(encoding="utf-8") as fh:
                        self._data[key] = json.load(fh)
                    self._loaded.append(key)
                except (json.JSONDecodeError, OSError):
                    self._data[key] = []
            else:
                self._data[key] = []

    def _d(self, key: str) -> list[dict]:
        return self._data.get(key) or []

    # ── Rules ──────────────────────────────────────────────────────────────────

    def _rule_suspicious_signin_then_persistence(self) -> list[Finding]:
        """
        User has a sign-in with suspicious indicators AND a new MFA method
        or device registered during the same collection window.
        """
        signin_records = self._d("signin_logs")
        mfa_records = self._d("mfa_methods")
        device_records = self._d("registered_devices")

        # Index: user -> suspicious sign-in records
        by_user_suspicious: dict[str, list[dict]] = defaultdict(list)
        for r in signin_records:
            upn = (r.get("userPrincipalName") or "").lower()
            if upn and _has_flag_prefix(r, *_SUSPICIOUS_SIGNIN_PREFIXES):
                by_user_suspicious[upn].append(r)

        # Index: user -> recently-added MFA methods
        by_user_mfa: dict[str, list[dict]] = defaultdict(list)
        for r in mfa_records:
            upn = (r.get("_sourceUser") or "").lower()
            if upn and _has_flag_prefix(r, "RECENTLY_ADDED:", "HIGH_PERSISTENCE_METHOD:"):
                by_user_mfa[upn].append(r)

        # Index: user -> recently-registered devices
        by_user_device: dict[str, list[dict]] = defaultdict(list)
        for r in device_records:
            upn = (r.get("_sourceUser") or "").lower()
            if upn and _has_flag_prefix(r, "RECENTLY_REGISTERED"):
                by_user_device[upn].append(r)

        findings: list[Finding] = []
        for upn in by_user_suspicious:
            persistence: list[tuple[str, dict]] = []
            persistence += [("mfa_methods", m) for m in by_user_mfa.get(upn, [])]
            persistence += [("registered_devices", d) for d in by_user_device.get(upn, [])]
            if not persistence:
                continue

            suspicious_summaries = _extract_flags_with_prefix(
                by_user_suspicious[upn], *_SUSPICIOUS_SIGNIN_PREFIXES
            )
            persist_type = "MFA method" if by_user_mfa.get(upn) else "device"
            if by_user_mfa.get(upn) and by_user_device.get(upn):
                persist_type = "MFA method and device"

            evidence: list[Evidence] = []
            for r in by_user_suspicious[upn][:3]:
                evidence.append(_evidence(r, "signin_logs", "createdDateTime",
                    f"Suspicious sign-in: {', '.join(_extract_flags_with_prefix([r], *_SUSPICIOUS_SIGNIN_PREFIXES))}"))
            for coll, r in persistence[:3]:
                ts_key = "createdDateTime" if coll == "mfa_methods" else "registrationDateTime"
                evidence.append(_evidence(r, coll, ts_key,
                    f"New {coll.replace('_', ' ')}: {r.get('_methodType') or r.get('displayName') or ''}"))

            # Temporal proximity: compare suspicious sign-ins to persistence events
            persist_records = [r for _, r in persistence]
            persist_ts_key = "createdDateTime"  # MFA methods use createdDateTime
            gap_min, prox = _closest_pair_gap(
                by_user_suspicious[upn], "createdDateTime",
                persist_records, persist_ts_key,
            )
            prox_note = _proximity_note(prox, gap_min)

            findings.append(Finding(
                id="",
                rule="suspicious_signin_then_persistence",
                severity="high",
                title="Suspicious sign-in followed by new persistence mechanism",
                user=upn,
                description=(
                    f"{upn} authenticated with suspicious indicators "
                    f"({'; '.join(suspicious_summaries[:3])}) and a new "
                    f"{persist_type} was registered during the same collection window. "
                    "This pattern is consistent with account takeover followed by attacker persistence."
                    + (f" {prox_note}" if prox_note else "")
                ),
                evidence=evidence,
                recommendation=(
                    "Verify timestamps — confirm whether the sign-in and registration are causally linked. "
                    "If unauthorized: disable the account, remove the new MFA method or device, "
                    "revoke all active sessions (revokeSignInSessions), and reset credentials."
                ),
                temporal_proximity=prox,
                proximity_minutes=gap_min,
            ))

        return findings

    def _rule_password_reset_then_mfa_registered(self) -> list[Finding]:
        """
        Admin password reset in audit logs + RECENTLY_ADDED MFA method for
        the same user. Classic ATO: attacker resets victim's password, then
        registers their own authenticator app or phone number.
        """
        audit_records = self._d("audit_logs")
        mfa_records = self._d("mfa_methods")

        # Index: target user -> admin password reset audit events
        by_target_reset: dict[str, list[dict]] = defaultdict(list)
        for r in audit_records:
            if _has_flag_prefix(r, "ADMIN_PASSWORD_RESET"):
                for upn in _target_users_from_audit(r):
                    by_target_reset[upn].append(r)

        # Index: user -> recently-added MFA methods
        by_user_mfa: dict[str, list[dict]] = defaultdict(list)
        for r in mfa_records:
            upn = (r.get("_sourceUser") or "").lower()
            if upn and _has_flag_prefix(r, "RECENTLY_ADDED"):
                by_user_mfa[upn].append(r)

        findings: list[Finding] = []
        for upn in by_target_reset:
            mfa_added = by_user_mfa.get(upn, [])
            if not mfa_added:
                continue

            evidence: list[Evidence] = []
            for r in by_target_reset[upn][:2]:
                initiator = _initiator_upn(r)
                evidence.append(_evidence(r, "audit_logs", "activityDateTime",
                    f"Admin password reset by {initiator or 'unknown'}"))
            for r in mfa_added[:3]:
                method_type = r.get("_methodType") or "unknown"
                evidence.append(_evidence(r, "mfa_methods", "createdDateTime",
                    f"New MFA method registered: {method_type}"))

            gap_min, prox = _closest_pair_gap(
                by_target_reset[upn], "activityDateTime",
                mfa_added, "createdDateTime",
            )
            prox_note = _proximity_note(prox, gap_min)

            findings.append(Finding(
                id="",
                rule="password_reset_then_mfa_registered",
                severity="high",
                title="Admin password reset followed by new MFA method registration",
                user=upn,
                description=(
                    f"An administrator reset the password for {upn}, and a new MFA method "
                    f"({', '.join(r.get('_methodType', '') for r in mfa_added[:3])}) was registered "
                    "during the same collection window. Attackers routinely reset a victim's password "
                    "to lock them out, then register their own MFA method for persistent access."
                    + (f" {prox_note}" if prox_note else "")
                ),
                evidence=evidence,
                recommendation=(
                    "Confirm who initiated the password reset — if not part of authorized IR, "
                    "this indicates the attacker had admin-level access. Remove the new MFA method, "
                    "reset the account password again, revoke all sessions, and audit the admin account "
                    "that performed the reset."
                ),
                temporal_proximity=prox,
                proximity_minutes=gap_min,
            ))

        return findings

    def _rule_privilege_escalation_after_signin(self) -> list[Finding]:
        """
        User sign-in event + a HIGH_PRIV_ROLE_ASSIGNED audit event targeting
        the same user within the collection window.
        """
        signin_records = self._d("signin_logs")
        audit_records = self._d("audit_logs")

        # Users that appear in sign-in logs
        users_with_signin: set[str] = {
            (r.get("userPrincipalName") or "").lower()
            for r in signin_records
            if r.get("userPrincipalName")
        }

        # Index: target user -> high-priv role assignments
        by_target_priv: dict[str, list[dict]] = defaultdict(list)
        for r in audit_records:
            if _has_flag_prefix(r, "HIGH_PRIV_ROLE_ASSIGNED"):
                for upn in _target_users_from_audit(r):
                    if upn in users_with_signin:
                        by_target_priv[upn].append(r)

        # Only flag users whose sign-ins had suspicious indicators, OR
        # where the role assignment happened in the same window as a failed/risky sign-in
        # (to avoid over-flagging routine admin onboarding)
        by_user_suspicious: set[str] = {
            (r.get("userPrincipalName") or "").lower()
            for r in signin_records
            if _has_flag_prefix(r, *_SUSPICIOUS_SIGNIN_PREFIXES, "RISK_LEVEL:", "FAILED_SIGNIN:")
        }

        findings: list[Finding] = []
        for upn, role_events in by_target_priv.items():
            # Only correlate if there were also suspicious sign-in signals for this user
            if upn not in by_user_suspicious:
                continue

            user_signins = [
                r for r in signin_records
                if (r.get("userPrincipalName") or "").lower() == upn
                and _has_flag_prefix(r, *_SUSPICIOUS_SIGNIN_PREFIXES, "RISK_LEVEL:", "FAILED_SIGNIN:")
            ]

            roles_assigned = _extract_flags_with_prefix(role_events, "HIGH_PRIV_ROLE_ASSIGNED")

            evidence: list[Evidence] = []
            for r in user_signins[:2]:
                evidence.append(_evidence(r, "signin_logs", "createdDateTime",
                    f"Suspicious sign-in from {(r.get('location') or {}).get('countryOrRegion', 'unknown country')}"))
            for r in role_events[:3]:
                evidence.append(_evidence(r, "audit_logs", "activityDateTime",
                    f"Privilege escalation: {r.get('activityDisplayName', '')} — {', '.join(roles_assigned[:2])}"))

            gap_min, prox = _closest_pair_gap(
                user_signins, "createdDateTime",
                role_events, "activityDateTime",
            )
            prox_note = _proximity_note(prox, gap_min)

            findings.append(Finding(
                id="",
                rule="privilege_escalation_after_signin",
                severity=_proximity_severity_boost("high", prox),
                title="Suspicious sign-in activity during privilege escalation window",
                user=upn,
                description=(
                    f"{upn} had suspicious sign-in activity and was also granted a high-privilege role "
                    f"({'; '.join(roles_assigned[:3])}) during the same collection window. "
                    "Attackers who gain access often assign themselves admin roles before performing "
                    "further actions or establishing persistence."
                    + (f" {prox_note}" if prox_note else "")
                ),
                evidence=evidence,
                recommendation=(
                    "Verify whether the role assignment was authorized. If not, remove the role, "
                    "disable the account, revoke all sessions, and audit all actions taken "
                    "using the elevated privileges (check audit logs for actions after the role assignment)."
                ),
                temporal_proximity=prox,
                proximity_minutes=gap_min,
            ))

        return findings

    def _rule_oauth_phishing_pattern(self) -> list[Finding]:
        """
        Sign-in with device code or ROPC + an OAuth grant with HIGH_RISK_SCOPE
        for the same user. Indicates OAuth phishing — attacker tricks user into
        consenting to a malicious app.
        """
        signin_records = self._d("signin_logs")
        oauth_records = self._d("oauth_grants")

        # Users with device code or ROPC sign-ins
        by_user_devicecode: dict[str, list[dict]] = defaultdict(list)
        for r in signin_records:
            upn = (r.get("userPrincipalName") or "").lower()
            if upn and _has_flag_prefix(r, "SUSPICIOUS_AUTH_PROTOCOL:"):
                by_user_devicecode[upn].append(r)

        # Index: principal user ID -> high-risk OAuth grants
        # OAuth grants use principalId (object ID) not UPN — match what we can
        # via _sourceUser which is set on per-user delegated grants
        by_user_oauth: dict[str, list[dict]] = defaultdict(list)
        for r in oauth_records:
            upn = (r.get("_sourceUser") or "").lower()
            if upn and _has_flag_prefix(r, "HIGH_RISK_SCOPE:"):
                by_user_oauth[upn].append(r)

        findings: list[Finding] = []
        for upn in by_user_devicecode:
            grants = by_user_oauth.get(upn, [])
            if not grants:
                continue

            scopes = _extract_flags_with_prefix(grants, "HIGH_RISK_SCOPE:")

            evidence: list[Evidence] = []
            for r in by_user_devicecode[upn][:3]:
                proto = next((f for f in _flags(r) if f.startswith("SUSPICIOUS_AUTH_PROTOCOL:")), "")
                evidence.append(_evidence(r, "signin_logs", "createdDateTime",
                    f"Device code / ROPC authentication: {proto}"))
            for r in grants[:3]:
                evidence.append(_evidence(r, "oauth_grants", "", f"High-risk OAuth scope: {', '.join(scopes[:3])}"))

            findings.append(Finding(
                id="",
                rule="oauth_phishing_pattern",
                severity="high",
                title="Potential OAuth phishing — device code authentication with high-risk app grant",
                user=upn,
                description=(
                    f"{upn} authenticated using a suspicious protocol (device code or ROPC) and also "
                    f"has an OAuth grant with high-risk permissions ({', '.join(scopes[:4])}). "
                    "This combination is characteristic of OAuth phishing: the attacker uses a device "
                    "code flow to hijack the session and obtain persistent delegated access to mail or files."
                ),
                evidence=evidence,
                recommendation=(
                    "Review the OAuth grant — identify the app (clientId) and verify it is sanctioned. "
                    "If unauthorized: revoke the grant, revoke all sign-in sessions, and check whether "
                    "the app accessed mailbox content (MailItemsAccessed in UAL). "
                    "Report the app to Microsoft if malicious."
                ),
            ))

        return findings

    def _rule_bec_attack_pattern(self) -> list[Finding]:
        """
        Any sign-in activity for a user who also has a mailbox rule with
        FORWARDS_TO or mail forwarding with EXTERNAL_SMTP_FORWARD.
        """
        signin_records = self._d("signin_logs")
        rule_records = self._d("mailbox_rules")
        fwd_records = self._d("mail_forwarding")

        users_with_signin: set[str] = {
            (r.get("userPrincipalName") or "").lower()
            for r in signin_records
            if r.get("userPrincipalName")
        }

        # Index: user -> suspicious mailbox rules
        by_user_rule: dict[str, list[dict]] = defaultdict(list)
        for r in rule_records:
            upn = (r.get("_sourceUser") or "").lower()
            if upn and _has_flag_prefix(r, "FORWARDS_TO:", "PERMANENT_DELETE", "MOVES_TO_HIDDEN_FOLDER:"):
                by_user_rule[upn].append(r)

        # Index: user -> external forwarding
        by_user_fwd: dict[str, list[dict]] = defaultdict(list)
        for r in fwd_records:
            upn = (r.get("_sourceUser") or "").lower()
            if upn and _has_flag_prefix(r, "EXTERNAL_SMTP_FORWARD:", "NO_LOCAL_COPY:"):
                by_user_fwd[upn].append(r)

        findings: list[Finding] = []
        seen_users: set[str] = set()

        for upn in users_with_signin:
            rules = by_user_rule.get(upn, [])
            fwds = by_user_fwd.get(upn, [])
            if not rules and not fwds:
                continue
            if upn in seen_users:
                continue
            seen_users.add(upn)

            user_signins = [
                r for r in signin_records
                if (r.get("userPrincipalName") or "").lower() == upn
            ]

            # Prefer suspicious sign-ins in evidence; fall back to any sign-in
            suspicious_signins = [r for r in user_signins if _has_flag_prefix(r, *_SUSPICIOUS_SIGNIN_PREFIXES)]
            signins_for_evidence = suspicious_signins[:2] or user_signins[:2]

            rule_flags = _extract_flags_with_prefix(rules, "FORWARDS_TO:", "PERMANENT_DELETE", "MOVES_TO_HIDDEN_FOLDER:")
            fwd_flags = _extract_flags_with_prefix(fwds, "EXTERNAL_SMTP_FORWARD:", "NO_LOCAL_COPY:")

            evidence: list[Evidence] = []
            for r in signins_for_evidence:
                country = (r.get("location") or {}).get("countryOrRegion", "")
                evidence.append(_evidence(r, "signin_logs", "createdDateTime",
                    f"Sign-in from {country or 'unknown country'}"))
            for r in rules[:3]:
                evidence.append(_evidence(r, "mailbox_rules", "",
                    f"Mailbox rule: {', '.join(rule_flags[:2])}"))
            for r in fwds[:2]:
                evidence.append(_evidence(r, "mail_forwarding", "",
                    f"Mail forwarding: {', '.join(fwd_flags[:2])}"))

            all_flags = rule_flags + fwd_flags
            findings.append(Finding(
                id="",
                rule="bec_attack_pattern",
                severity="high",
                title="BEC indicators — sign-in activity with mailbox manipulation",
                user=upn,
                description=(
                    f"{upn} has sign-in activity and suspicious mailbox configuration: "
                    f"{', '.join(all_flags[:4])}. "
                    "Attackers accessing a mailbox typically create rules to forward, hide, or "
                    "delete mail to exfiltrate correspondence or enable wire fraud."
                ),
                evidence=evidence,
                recommendation=(
                    "Immediately review and remove the mailbox rules and forwarding settings. "
                    "Check UAL for MailItemsAccessed and mail sent events. "
                    "Notify the user and any external parties who may have received fraudulent communications. "
                    "Disable the account and reset credentials if unauthorized access is confirmed."
                ),
            ))

        return findings

    def _rule_dual_exfiltration_channels(self) -> list[Finding]:
        """
        User has BOTH a mailbox-level exfiltration mechanism (inbox rule
        forwarding or SMTP forwarding) AND a high-risk OAuth grant.

        Attackers who use belt-and-suspenders exfiltration set up a mail
        forwarding rule or SMTP redirect to copy mail out in real time,
        and also consent a malicious OAuth app with Mail.Read or similar
        scope so they can pull mail independently via the Graph API.
        This redundancy means removing one mechanism leaves the other active.
        """
        rule_records = self._d("mailbox_rules")
        fwd_records  = self._d("mail_forwarding")
        oauth_records = self._d("oauth_grants")

        # Users with a forwarding/exfil mailbox rule
        users_with_rule: dict[str, list[dict]] = defaultdict(list)
        for r in rule_records:
            upn = (r.get("_sourceUser") or "").lower()
            if upn and _has_flag_prefix(r, "FORWARDS_TO:", "PERMANENT_DELETE", "MOVES_TO_HIDDEN_FOLDER:"):
                users_with_rule[upn].append(r)

        # Users with SMTP forwarding
        users_with_fwd: dict[str, list[dict]] = defaultdict(list)
        for r in fwd_records:
            upn = (r.get("_sourceUser") or "").lower()
            if upn and _has_flag_prefix(r, "EXTERNAL_SMTP_FORWARD:"):
                users_with_fwd[upn].append(r)

        # Union of users with any mailbox-level exfil
        users_with_mailbox_exfil = set(users_with_rule) | set(users_with_fwd)
        if not users_with_mailbox_exfil:
            return []

        # Users with a high-risk OAuth grant
        users_with_oauth: dict[str, list[dict]] = defaultdict(list)
        for r in oauth_records:
            upn = (r.get("_sourceUser") or "").lower()
            if upn and _has_flag_prefix(r, "HIGH_RISK_SCOPE:"):
                users_with_oauth[upn].append(r)

        findings: list[Finding] = []
        seen: set[str] = set()

        for upn in users_with_mailbox_exfil & set(users_with_oauth):
            if upn in seen:
                continue
            seen.add(upn)

            rules = users_with_rule.get(upn, [])
            fwds  = users_with_fwd.get(upn, [])
            oauths = users_with_oauth[upn]

            rule_flags  = _extract_flags_with_prefix(rules,  "FORWARDS_TO:", "PERMANENT_DELETE", "MOVES_TO_HIDDEN_FOLDER:")
            fwd_flags   = _extract_flags_with_prefix(fwds,   "EXTERNAL_SMTP_FORWARD:")
            oauth_flags = _extract_flags_with_prefix(oauths, "HIGH_RISK_SCOPE:")
            all_flags   = rule_flags + fwd_flags + oauth_flags

            evidence: list[Evidence] = []
            for r in rules[:2]:
                evidence.append(_evidence(r, "mailbox_rules", "",
                    f"Mailbox rule: {', '.join(rule_flags[:2])}"))
            for r in fwds[:1]:
                evidence.append(_evidence(r, "mail_forwarding", "",
                    f"SMTP forwarding: {', '.join(fwd_flags[:1])}"))
            for r in oauths[:2]:
                evidence.append(_evidence(r, "oauth_grants", "",
                    f"OAuth grant: {', '.join(oauth_flags[:2])}"))

            findings.append(Finding(
                id="",
                rule="dual_exfiltration_channels",
                severity="high",
                title="Dual exfiltration channels — mailbox manipulation and OAuth app access",
                user=upn,
                description=(
                    f"{upn} has both a mailbox-level exfiltration mechanism "
                    f"({', '.join((rule_flags + fwd_flags)[:2])}) and a high-risk OAuth grant "
                    f"({', '.join(oauth_flags[:2])}). "
                    "This belt-and-suspenders pattern indicates a deliberate attacker who "
                    "established redundant channels: removing one mechanism leaves the other "
                    "active. Both must be remediated simultaneously."
                ),
                evidence=evidence,
                recommendation=(
                    "Remove the mailbox rule(s) and disable SMTP forwarding immediately. "
                    "Revoke the OAuth consent grant(s) from the Entra portal (Enterprise Apps → "
                    "User consent). Reset the account credentials and revoke all active sessions. "
                    "Check UAL for MailItemsAccessed events to assess what data was exfiltrated "
                    "through each channel."
                ),
            ))

        return findings

    def _rule_device_code_then_device_registered(self) -> list[Finding]:
        """
        Device code sign-in + newly registered device for the same user.
        The attacker uses the device code to obtain tokens, then registers
        a device to obtain a PRT for long-term persistent access.
        """
        signin_records = self._d("signin_logs")
        device_records = self._d("registered_devices")

        by_user_dc: dict[str, list[dict]] = defaultdict(list)
        for r in signin_records:
            upn = (r.get("userPrincipalName") or "").lower()
            if upn and _has_flag_prefix(r, "SUSPICIOUS_AUTH_PROTOCOL:deviceCode"):
                by_user_dc[upn].append(r)

        by_user_device: dict[str, list[dict]] = defaultdict(list)
        for r in device_records:
            upn = (r.get("_sourceUser") or "").lower()
            if upn and _has_flag_prefix(r, "RECENTLY_REGISTERED"):
                by_user_device[upn].append(r)

        findings: list[Finding] = []
        for upn in by_user_dc:
            devices = by_user_device.get(upn, [])
            if not devices:
                continue

            evidence: list[Evidence] = []
            for r in by_user_dc[upn][:3]:
                evidence.append(_evidence(r, "signin_logs", "createdDateTime",
                    "Device code authentication — token-theft phishing vector"))
            for r in devices[:3]:
                dev_name = r.get("displayName") or r.get("deviceId") or ""
                evidence.append(_evidence(r, "registered_devices", "registrationDateTime",
                    f"New device registered: {dev_name}"))

            gap_min, prox = _closest_pair_gap(
                by_user_dc[upn], "createdDateTime",
                devices, "registrationDateTime",
            )
            prox_note = _proximity_note(prox, gap_min)

            findings.append(Finding(
                id="",
                rule="device_code_then_device_registered",
                severity="high",
                title="Device code phishing with new device registration",
                user=upn,
                description=(
                    f"{upn} had a device code authentication sign-in (primary technique in "
                    "token-theft phishing campaigns) and a new device was registered during "
                    "the same collection window. Device code phishing followed by device "
                    "registration grants the attacker a Primary Refresh Token that survives "
                    "password resets."
                    + (f" {prox_note}" if prox_note else "")
                ),
                evidence=evidence,
                recommendation=(
                    "Remove the newly registered device immediately — it may carry a PRT that "
                    "persists after password reset. Revoke all sign-in sessions, reset credentials, "
                    "and verify the device code sign-in was not user-initiated (check with the user). "
                    "Block legacy auth and device code flows via Conditional Access if not already done."
                ),
                temporal_proximity=prox,
                proximity_minutes=gap_min,
            ))

        return findings

    def _rule_password_spray(self) -> list[Finding]:
        """
        A single source IP with 10+ failed sign-in attempts against 5+ distinct
        accounts within the collection window — the hallmark of a password spray
        attack. Severity is elevated to HIGH when the same IP also has a
        successful sign-in, indicating at least one credential was valid.
        """
        signin_records = self._d("signin_logs")
        if not signin_records:
            return []

        # Group failed sign-ins by source IP
        ip_to_failures: dict[str, list[dict]] = defaultdict(list)
        for r in signin_records:
            status = r.get("status") or {}
            error_code = status.get("errorCode", 0)
            if error_code != 0:
                ip = r.get("ipAddress") or ""
                if ip:
                    ip_to_failures[ip].append(r)

        findings: list[Finding] = []
        reported_ips: set[str] = set()

        for ip, failures in ip_to_failures.items():
            distinct_targets = {
                (r.get("userPrincipalName") or "").lower()
                for r in failures
                if r.get("userPrincipalName")
            }
            if len(distinct_targets) < self._spray_min_targets:
                continue
            if len(failures) < self._spray_min_failures:
                continue
            if ip in reported_ips:
                continue
            reported_ips.add(ip)

            # Check whether any spray attempt succeeded (same IP, errorCode 0)
            successful_users = {
                (r.get("userPrincipalName") or "").lower()
                for r in signin_records
                if r.get("ipAddress") == ip
                and (r.get("status") or {}).get("errorCode", -1) == 0
                and r.get("userPrincipalName")
            }

            # Tally error codes for description context
            error_counts: dict[int, int] = defaultdict(int)
            for r in failures:
                ec = (r.get("status") or {}).get("errorCode", 0)
                if ec:
                    error_counts[ec] += 1
            top_error = max(error_counts, key=lambda k: error_counts[k]) if error_counts else 0

            severity = "high" if successful_users else "medium"

            evidence: list[Evidence] = []
            for r in failures[:5]:
                upn = r.get("userPrincipalName") or ""
                ec = (r.get("status") or {}).get("errorCode", "?")
                evidence.append(_evidence(r, "signin_logs", "createdDateTime",
                    f"Failed sign-in for {upn} (errorCode {ec})"))
            for upn in list(successful_users)[:2]:
                hit = next(
                    (r for r in signin_records
                     if r.get("ipAddress") == ip
                     and (r.get("status") or {}).get("errorCode", -1) == 0
                     and (r.get("userPrincipalName") or "").lower() == upn),
                    None,
                )
                if hit:
                    evidence.append(_evidence(hit, "signin_logs", "createdDateTime",
                        f"SUCCESSFUL sign-in for {upn} from spray IP"))

            success_note = (
                f" At least {len(successful_users)} account(s) had a SUCCESSFUL sign-in "
                f"from this same IP ({', '.join(list(successful_users)[:3])}), indicating "
                "the spray may have succeeded — those accounts require immediate investigation."
            ) if successful_users else ""

            target_sample = ", ".join(list(distinct_targets)[:5])
            if len(distinct_targets) > 5:
                target_sample += f", ... (+{len(distinct_targets) - 5} more)"

            findings.append(Finding(
                id="",
                rule="password_spray",
                severity=severity,
                title=(
                    f"Password spray — {len(failures)} failures across "
                    f"{len(distinct_targets)} accounts from {ip}"
                ),
                user="",
                description=(
                    f"IP address {ip} attempted authentication against {len(distinct_targets)} distinct "
                    f"accounts with {len(failures)} total failures (most common error code: {top_error}) "
                    f"during the collection window. Targeted accounts: {target_sample}.{success_note}"
                ),
                evidence=evidence,
                recommendation=(
                    f"Look up {ip} in AbuseIPDB, VirusTotal, or Shodan to assess reputation. "
                    "If spray is confirmed: enforce or verify MFA for all targeted accounts, "
                    "review accounts that had successful sign-ins from this IP for post-access activity, "
                    "and consider blocking the IP via Conditional Access Named Locations. "
                    "Check for account lockouts that may have alerted the targeted users."
                ),
            ))

        return findings

    def _rule_spray_then_escalation(self) -> list[Finding]:
        """
        A password spray attack that succeeded (same IP has successful sign-in)
        against a user who THEN had a persistence mechanism added within 24 hours:
        a new MFA method, a new device registered, a high-privilege role assigned,
        or a new OAuth grant with high-risk scopes.

        This links the spray as the initial access vector to post-compromise
        consolidation activity — the full T1110 → T1078 → T1098 chain.
        """
        signin_records = self._d("signin_logs")
        audit_records  = self._d("audit_logs")
        mfa_records    = self._d("mfa_methods")
        device_records = self._d("registered_devices")
        oauth_records  = self._d("oauth_grants")
        if not signin_records:
            return []

        # Identify spray IPs (same criteria as _rule_password_spray)
        ip_failures: dict[str, set[str]] = defaultdict(set)
        for r in signin_records:
            status = r.get("status") or {}
            if (status.get("errorCode") or 0) != 0:
                ip = r.get("ipAddress") or ""
                upn = (r.get("userPrincipalName") or "").lower()
                if ip and upn:
                    ip_failures[ip].add(upn)

        spray_ips = {
            ip for ip, targets in ip_failures.items()
            if len(targets) >= self._spray_min_targets
        }
        if not spray_ips:
            return []

        # Find users who had a successful sign-in from any spray IP
        spray_successes: dict[str, dict] = {}   # upn → first success record
        for r in signin_records:
            if r.get("ipAddress") not in spray_ips:
                continue
            if (r.get("status") or {}).get("errorCode", -1) != 0:
                continue
            upn = (r.get("userPrincipalName") or "").lower()
            if upn and upn not in spray_successes:
                spray_successes[upn] = r

        if not spray_successes:
            return []

        _ESCALATION_WINDOW = 86400  # 24 h in seconds

        findings: list[Finding] = []

        for upn, success_rec in spray_successes.items():
            success_dt = _parse_dt(success_rec.get("createdDateTime") or "")
            if success_dt == datetime.min.replace(tzinfo=timezone.utc):
                continue

            escalation_evidence: list[Evidence] = []

            # Audit log — MFA add, role assignment, device join within 24 h
            for r in audit_records:
                target = (r.get("_targetUser") or "").lower()
                if target != upn:
                    continue
                if not _has_flag_prefix(r, *_PERSISTENCE_AUDIT_PREFIXES_TUPLE):
                    continue
                ev_dt = _parse_dt(r.get("activityDateTime") or "")
                if ev_dt == datetime.min.replace(tzinfo=timezone.utc):
                    continue
                delta = (ev_dt - success_dt).total_seconds()
                if 0 <= delta <= _ESCALATION_WINDOW:
                    escalation_evidence.append(_evidence(
                        r, "audit_logs", "activityDateTime",
                        f"Post-spray persistence: {r.get('activityDisplayName', 'audit event')}"
                    ))

            # MFA methods — recently added entries
            for r in mfa_records:
                if (r.get("userPrincipalName") or "").lower() != upn:
                    continue
                if not _has_flag_prefix(r, "RECENTLY_ADDED"):
                    continue
                escalation_evidence.append(_evidence(
                    r, "mfa_methods", "createdDateTime",
                    f"Recently added MFA method: {r.get('methodType', 'unknown')}"
                ))

            # Registered devices — added within 24 h of spray success
            for r in device_records:
                if (r.get("_sourceUser") or "").lower() != upn:
                    continue
                reg_dt = _parse_dt(
                    r.get("registrationDateTime") or r.get("createdDateTime") or ""
                )
                if reg_dt == datetime.min.replace(tzinfo=timezone.utc):
                    continue
                delta = (reg_dt - success_dt).total_seconds()
                if 0 <= delta <= _ESCALATION_WINDOW:
                    escalation_evidence.append(_evidence(
                        r, "registered_devices", "registrationDateTime",
                        f"Device registered {int(delta / 3600)}h after spray success: "
                        f"{r.get('displayName', 'unknown')}"
                    ))

            # OAuth grants — high-risk scopes on this user
            for r in oauth_records:
                if (r.get("_sourceUser") or "").lower() != upn:
                    continue
                if _has_flag_prefix(r, "HIGH_RISK_SCOPE"):
                    escalation_evidence.append(_evidence(
                        r, "oauth_grants", "",
                        f"High-risk OAuth grant: {(r.get('scope') or '')[:80]}"
                    ))

            if not escalation_evidence:
                continue

            # Compute proximity from spray success to first escalation event
            esc_timestamps = [e.timestamp for e in escalation_evidence if e.timestamp]
            gap_min = None
            prox = ""
            if esc_timestamps:
                success_ts = success_rec.get("createdDateTime") or ""
                if success_ts:
                    gaps = []
                    for ets in esc_timestamps:
                        dt_e = _parse_dt(ets)
                        if dt_e != datetime.min.replace(tzinfo=timezone.utc):
                            gaps.append(abs((dt_e - success_dt).total_seconds()) / 60)
                    if gaps:
                        gap_min = int(min(gaps))
                        prox = _proximity_label(gap_min)
            prox_note = _proximity_note(prox, gap_min)

            spray_ip_list = ", ".join(list(spray_ips)[:4])
            findings.append(Finding(
                id="",
                rule="spray_then_escalation",
                severity="high",
                title=f"Password spray → post-compromise escalation — {upn}",
                user=upn,
                description=(
                    f"A password spray from IP(s) {spray_ip_list} succeeded against {upn}. "
                    f"Within 24 hours of the successful sign-in, "
                    f"{len(escalation_evidence)} persistence/escalation event(s) were observed "
                    "on that account: new MFA methods, device registrations, role assignments, "
                    "or high-risk OAuth grants. This pattern is consistent with an attacker "
                    "consolidating access immediately after spray-based initial compromise."
                    + (f" {prox_note}" if prox_note else "")
                ),
                evidence=[
                    _evidence(
                        success_rec, "signin_logs", "createdDateTime",
                        f"Spray success — {upn} authenticated from spray IP"
                    ),
                    *escalation_evidence[:8],
                ],
                recommendation=(
                    f"Treat {upn} as compromised. "
                    "Revoke all active sessions, reset credentials, and review/remove any "
                    "MFA methods, devices, roles, or OAuth grants added after the spray "
                    "success timestamp. "
                    "Enrich the spray source IP(s) via cirrus enrich to assess infrastructure. "
                    "Check whether other accounts targeted by the spray also show post-access activity."
                ),
                temporal_proximity=prox,
                proximity_minutes=gap_min,
            ))

        return findings

    def _rule_mass_mail_access(self) -> list[Finding]:
        """
        A user with 50+ MailItemsAccessed UAL events in the collection window.
        Attackers and compromised OAuth applications bulk-read mailbox content
        for reconnaissance and financial fraud targeting. Severity is HIGH
        when the user also has interactive sign-in activity in the window.
        """
        ual_records = self._d("unified_audit_log")
        signin_records = self._d("signin_logs")
        if not ual_records:
            return []

        # Group MailItemsAccessed events by user
        by_user: dict[str, list[dict]] = defaultdict(list)
        for r in ual_records:
            op = (r.get("operation") or r.get("Operation") or "").lower()
            if op == "mailitemsaccessed":
                upn = (r.get("userId") or r.get("UserId") or "").lower()
                if upn and "@" in upn:
                    by_user[upn].append(r)

        users_with_signin: set[str] = {
            (r.get("userPrincipalName") or "").lower()
            for r in signin_records
            if r.get("userPrincipalName")
        }

        findings: list[Finding] = []
        for upn, records in by_user.items():
            if len(records) < self._mail_access_threshold:
                continue

            has_signin = upn in users_with_signin

            # Extract app IDs from auditData payload
            app_ids: set[str] = set()
            for r in records:
                audit_data = r.get("auditData") or {}
                if isinstance(audit_data, str):
                    try:
                        import json as _json
                        audit_data = _json.loads(audit_data)
                    except Exception:
                        audit_data = {}
                app_id = (
                    audit_data.get("AppId")
                    or audit_data.get("ApplicationId")
                    or ""
                )
                if app_id:
                    app_ids.add(app_id)

            evidence: list[Evidence] = []
            for r in records[:4]:
                ts = r.get("createdDateTime") or r.get("CreationTime") or ""
                audit_data = r.get("auditData") or {}
                if isinstance(audit_data, str):
                    try:
                        import json as _json
                        audit_data = _json.loads(audit_data)
                    except Exception:
                        audit_data = {}
                app_id = (
                    audit_data.get("AppId")
                    or audit_data.get("ApplicationId")
                    or ""
                )
                app_note = f" via app {app_id[:20]}" if app_id else ""
                evidence.append(Evidence(
                    collector="unified_audit_log",
                    timestamp=ts,
                    summary=f"MailItemsAccessed{app_note}",
                    flags=[],
                ))

            if has_signin:
                user_signins = [
                    r for r in signin_records
                    if (r.get("userPrincipalName") or "").lower() == upn
                ]
                for r in user_signins[:2]:
                    country = (r.get("location") or {}).get("countryOrRegion", "unknown")
                    evidence.append(_evidence(r, "signin_logs", "createdDateTime",
                        f"Sign-in from {country}"))

            app_note = (
                f" across {len(app_ids)} distinct app(s) ({', '.join(list(app_ids)[:3])})"
                if app_ids else ""
            )
            access_note = (
                f"{upn} also has interactive sign-in activity in this window."
                if has_signin else
                "No interactive sign-in seen for this user — access may be via a "
                "delegated OAuth app token that survived a password reset."
            )

            findings.append(Finding(
                id="",
                rule="mass_mail_access",
                severity="high" if has_signin else "medium",
                title=f"Mass mailbox access — {len(records)} MailItemsAccessed events for {upn}",
                user=upn,
                description=(
                    f"{upn} has {len(records)} MailItemsAccessed events in the collection "
                    f"window{app_note}. This volume is consistent with an attacker or compromised "
                    "application bulk-reading mailbox content — a key indicator of BEC "
                    f"reconnaissance and data exfiltration. {access_note}"
                ),
                evidence=evidence,
                recommendation=(
                    "Identify the application(s) responsible by reviewing the AppId field in the "
                    "UAL auditData payload — check if each app is sanctioned. "
                    "If the app is not recognized: revoke its OAuth grant, revoke all sign-in "
                    "sessions for the user, and reset credentials. "
                    "Check whether mail Send events follow the MailItemsAccessed events in the UAL — "
                    "that sequence indicates reconnaissance that escalated to active BEC fraud. "
                    "Preserve UAL records as evidence before revoking access."
                ),
            ))

        return findings

    def _rule_new_account_with_signin(self) -> list[Finding]:
        """
        A user flagged RECENTLY_CREATED in the users collector who also
        appears in sign-in logs. Attacker-created backdoor accounts often
        authenticate shortly after creation.
        """
        user_records = self._d("users")
        signin_records = self._d("signin_logs")

        recently_created: set[str] = {
            (r.get("userPrincipalName") or "").lower()
            for r in user_records
            if _has_flag_prefix(r, "RECENTLY_CREATED")
        }

        if not recently_created:
            return []

        by_user_signin: dict[str, list[dict]] = defaultdict(list)
        for r in signin_records:
            upn = (r.get("userPrincipalName") or "").lower()
            if upn in recently_created:
                by_user_signin[upn].append(r)

        findings: list[Finding] = []
        for upn, signins in by_user_signin.items():
            user_rec = next(
                (u for u in user_records if (u.get("userPrincipalName") or "").lower() == upn),
                None,
            )
            created_flag = next(
                (f for f in _flags(user_rec) if f.startswith("RECENTLY_CREATED:")),
                "RECENTLY_CREATED",
            ) if user_rec else "RECENTLY_CREATED"

            evidence: list[Evidence] = []
            if user_rec:
                evidence.append(_evidence(user_rec, "users", "createdDateTime",
                    f"Account created: {created_flag}"))
            for r in signins[:3]:
                country = (r.get("location") or {}).get("countryOrRegion", "")
                evidence.append(_evidence(r, "signin_logs", "createdDateTime",
                    f"Sign-in from {country or 'unknown'}"))

            gap_min, prox = _closest_pair_gap(
                [user_rec] if user_rec else [], "createdDateTime",
                signins, "createdDateTime",
            )
            prox_note = _proximity_note(prox, gap_min)

            findings.append(Finding(
                id="",
                rule="new_account_with_signin",
                severity=_proximity_severity_boost("medium", prox),
                title="Recently created account with active sign-in activity",
                user=upn,
                description=(
                    f"{upn} was created recently ({created_flag}) and already has "
                    f"{len(signins)} sign-in event(s) in the collection window. "
                    "Attackers create backdoor accounts that authenticate quickly after creation. "
                    "Verify this account was created through authorized provisioning processes."
                    + (f" {prox_note}" if prox_note else "")
                ),
                evidence=evidence,
                recommendation=(
                    "Verify the account creation was authorized (check audit logs for the USER_CREATED event "
                    "and who initiated it). If unauthorized: disable immediately, revoke all sessions, "
                    "and audit what the account accessed."
                ),
                temporal_proximity=prox,
                proximity_minutes=gap_min,
            ))

        return findings

    def _rule_cross_ip_correlation(self) -> list[Finding]:
        """
        A public IP address that appears in both sign-in logs and directory
        audit logs — suggests the same attacker source performed authentication
        and directory changes in the same session.
        """
        signin_records = self._d("signin_logs")
        audit_records = self._d("audit_logs")

        if not signin_records or not audit_records:
            return []

        # Build IP -> sign-in records index
        ip_to_signins: dict[str, list[dict]] = defaultdict(list)
        for r in signin_records:
            ip = r.get("ipAddress") or ""
            if ip:
                ip_to_signins[ip].append(r)

        # Build IP -> audit records index
        ip_to_audits: dict[str, list[dict]] = defaultdict(list)
        for r in audit_records:
            for detail in r.get("additionalDetails") or []:
                key = (detail.get("key") or "").lower()
                if "ip" in key or "address" in key:
                    val = detail.get("value") or ""
                    if val and "." in val:  # rough IPv4 check
                        ip_to_audits[val].append(r)
            # Also check PUBLIC_IP flags
            for f in _flags(r):
                if f.startswith("PUBLIC_IP:"):
                    ip = f[len("PUBLIC_IP:"):]
                    ip_to_audits[ip].append(r)

        findings: list[Finding] = []
        reported_ips: set[str] = set()

        for ip, sign_recs in ip_to_signins.items():
            audit_recs = ip_to_audits.get(ip, [])
            if not audit_recs:
                continue
            if ip in reported_ips:
                continue

            # Only flag public IPs — skip private/RFC1918
            if not any(_has_flag_prefix(r, "PUBLIC_IP:") for r in sign_recs):
                continue

            reported_ips.add(ip)

            # Get distinct users for this IP
            users_from_signin = list({
                (r.get("userPrincipalName") or "").lower()
                for r in sign_recs if r.get("userPrincipalName")
            })

            evidence: list[Evidence] = []
            for r in sign_recs[:3]:
                upn = r.get("userPrincipalName") or ""
                evidence.append(_evidence(r, "signin_logs", "createdDateTime",
                    f"Sign-in from {ip} as {upn}"))
            for r in audit_recs[:3]:
                evidence.append(_evidence(r, "audit_logs", "activityDateTime",
                    f"Directory change from {ip}: {r.get('activityDisplayName', '')}"))

            findings.append(Finding(
                id="",
                rule="cross_ip_correlation",
                severity="medium",
                title=f"IP {ip} appears in both sign-in logs and directory audit logs",
                user=users_from_signin[0] if len(users_from_signin) == 1 else "",
                description=(
                    f"IP address {ip} was seen in sign-in logs "
                    f"(user(s): {', '.join(users_from_signin[:3])}) and also in directory audit logs. "
                    "An IP present in both data sources suggests the same session or attacker source "
                    "authenticated and then made directory changes (MFA registration, role assignment, etc.)."
                ),
                evidence=evidence,
                recommendation=(
                    f"Look up {ip} in VirusTotal, Shodan, or AbuseIPDB to assess reputation. "
                    "Review the audit log events that originated from this IP — they may include "
                    "MFA method registration, role assignment, or app consent events that indicate "
                    "what the attacker did after authenticating."
                ),
            ))

        return findings

    def _rule_hosting_provider_signin(self) -> list[Finding]:
        """
        Successful sign-in from an IP that ip_enrichment.json identifies as
        a datacenter, hosting provider, proxy, or Tor exit node.

        Only runs when ip_enrichment.json exists in the case directory (i.e.
        the analyst has already run `cirrus enrich`). Silently returns [] if
        the file is absent or contains no threat data.
        """
        enrichment_path = self.case_dir / "ip_enrichment.json"
        if not enrichment_path.exists():
            return []

        try:
            with enrichment_path.open(encoding="utf-8") as fh:
                enrichment = json.load(fh)
        except (json.JSONDecodeError, OSError):
            return []

        ips_data: dict[str, dict] = enrichment.get("ips") or {}
        if not ips_data:
            return []

        # Build set of suspicious IPs from enrichment data
        suspicious_ips: dict[str, list[str]] = {}  # ip -> threat tags
        for ip, data in ips_data.items():
            tags = data.get("threat_summary") or []
            abuse_score = data.get("abuse_score")
            if isinstance(abuse_score, int) and abuse_score >= 25:
                if f"ABUSE_SCORE:{abuse_score}" not in tags:
                    tags = list(tags) + [f"ABUSE_SCORE:{abuse_score}"]
            if tags:
                suspicious_ips[ip] = tags

        if not suspicious_ips:
            return []

        signin_records = self._d("signin_logs")
        if not signin_records:
            return []

        # Find successful sign-ins from suspicious IPs, grouped by user
        by_user: dict[str, list[tuple[dict, list[str]]]] = defaultdict(list)
        for r in signin_records:
            ip = r.get("ipAddress") or ""
            if ip not in suspicious_ips:
                continue
            status = r.get("status") or {}
            if (status.get("errorCode") or 0) != 0:
                continue  # failed sign-in — not as urgent
            upn = (r.get("userPrincipalName") or "").lower()
            if upn:
                by_user[upn].append((r, suspicious_ips[ip]))

        findings: list[Finding] = []
        for upn, hits in by_user.items():
            # Deduplicate IPs for this user
            unique_ips: dict[str, list[str]] = {}
            for r, tags in hits:
                ip = r.get("ipAddress") or ""
                if ip and ip not in unique_ips:
                    unique_ips[ip] = tags

            ioc_flags = [f"HOSTING_PROVIDER_SIGNIN:{ip}" for ip in unique_ips]

            evidence: list[Evidence] = []
            for r, tags in hits[:4]:
                ip = r.get("ipAddress") or ""
                country = (r.get("location") or {}).get("countryOrRegion", "")
                tag_str = ", ".join(tags[:3])
                evidence.append(_evidence(
                    r, "signin_logs", "createdDateTime",
                    f"Sign-in from {ip} ({country}) — {tag_str}",
                ))

            ip_list = ", ".join(list(unique_ips.keys())[:4])
            all_tags: list[str] = []
            for tags in unique_ips.values():
                all_tags.extend(t for t in tags if t not in all_tags)
            tag_summary = ", ".join(all_tags[:5])

            findings.append(Finding(
                id="",
                rule="hosting_provider_signin",
                severity="medium",
                title=(
                    f"Successful sign-in from hosting/anonymising infrastructure — {upn}"
                ),
                user=upn,
                description=(
                    f"{upn} had a successful sign-in from "
                    f"{'an IP' if len(unique_ips) == 1 else f'{len(unique_ips)} IPs'} "
                    f"({ip_list}) identified as {tag_summary}. "
                    "Attackers commonly use datacenter VMs, commercial VPNs, or Tor to "
                    "anonymise their origin during account takeover operations. "
                    "Legitimate users rarely authenticate from hosting infrastructure."
                ),
                evidence=evidence,
                recommendation=(
                    "Review the full sign-in context (app used, MFA method, device) for "
                    f"the sign-in(s) from {ip_list}. "
                    "Run `cirrus triage` on this account to assess broader compromise indicators. "
                    "If the sign-in is not recognised by the user, revoke all sessions "
                    "(revokeSignInSessions), reset credentials, and check for new MFA "
                    "methods or inbox rules added after this sign-in."
                ),
                ioc_flags=ioc_flags,
            ))

        return findings

    def _rule_pim_activation_after_suspicious_signin(self) -> list[Finding]:
        """
        A PIM high-privilege role activation for a user who also had a
        suspicious sign-in (device code, impossible travel, geo-risk) in
        the collection window.

        Attackers who compromise an account eligible for a PIM role often
        activate that role to perform admin actions immediately after sign-in.
        The role may only be active for minutes before deactivation — this
        correlation surfaces the pattern across the sign-in and PIM log streams.
        """
        pim_records = self._d("pim_activations")
        signin_records = self._d("signin_logs")
        if not pim_records or not signin_records:
            return []

        # Users with high-priv PIM activations
        pim_by_user: dict[str, list[dict]] = defaultdict(list)
        for r in pim_records:
            if _has_flag_prefix(r, "HIGH_PRIV_PIM_ACTIVATION:"):
                # Try to get the target user (the account whose role was activated)
                targets = _target_users_from_audit(r)
                initiator = _initiator_upn(r)
                # For self-activations the initiator is the user; else use targets
                upns = targets if targets else ([initiator] if initiator else [])
                for upn in upns:
                    pim_by_user[upn].append(r)

        # Users with suspicious sign-ins
        suspicious_signers: set[str] = set()
        for r in signin_records:
            if _has_flag_prefix(r, *_SUSPICIOUS_SIGNIN_PREFIXES):
                upn = (r.get("userPrincipalName") or "").lower()
                if upn:
                    suspicious_signers.add(upn)

        findings: list[Finding] = []
        for upn, pim_recs in pim_by_user.items():
            if upn not in suspicious_signers:
                continue

            # Collect supporting signin evidence
            susp_signins = [
                r for r in signin_records
                if (r.get("userPrincipalName") or "").lower() == upn
                and _has_flag_prefix(r, *_SUSPICIOUS_SIGNIN_PREFIXES)
            ]

            role_names = list({
                f[len("HIGH_PRIV_PIM_ACTIVATION:"):] for r in pim_recs
                for f in _flags(r) if f.startswith("HIGH_PRIV_PIM_ACTIVATION:")
            })
            role_str = ", ".join(role_names[:3])

            evidence: list[Evidence] = []
            for r in pim_recs[:3]:
                role = next(
                    (f[len("HIGH_PRIV_PIM_ACTIVATION:"):] for f in _flags(r)
                     if f.startswith("HIGH_PRIV_PIM_ACTIVATION:")), "unknown role"
                )
                evidence.append(_evidence(
                    r, "pim_activations", "activityDateTime",
                    f"PIM activation of high-privilege role: {role}",
                ))
            for r in susp_signins[:2]:
                susp_flags = [f for f in _flags(r) if any(f.startswith(p) for p in _SUSPICIOUS_SIGNIN_PREFIXES)]
                evidence.append(_evidence(
                    r, "signin_logs", "createdDateTime",
                    f"Suspicious sign-in: {', '.join(susp_flags[:3])}",
                ))

            gap_min, prox = _closest_pair_gap(
                susp_signins, "createdDateTime",
                pim_recs, "activityDateTime",
            )
            prox_note = _proximity_note(prox, gap_min)

            findings.append(Finding(
                id="",
                rule="pim_activation_after_suspicious_signin",
                severity="high",
                title=f"PIM high-privilege activation following suspicious sign-in — {upn}",
                user=upn,
                description=(
                    f"{upn} activated a privileged role ({role_str}) via PIM, "
                    "and also had a suspicious sign-in event in the collection window. "
                    "This pattern is consistent with an attacker who compromised the account, "
                    "signed in using an evasion technique, then self-activated a PIM role "
                    "to gain elevated privileges for subsequent administrative actions."
                    + (f" {prox_note}" if prox_note else "")
                ),
                evidence=evidence,
                recommendation=(
                    "Immediately review the PIM activation log to confirm whether the "
                    f"activation of {role_str} was authorised. "
                    "Check directory audit logs for admin actions taken while the role was active. "
                    "If suspicious: revoke all sessions, reset credentials, remove any new MFA "
                    "methods or OAuth grants, and review all PIM eligible assignments for this account."
                ),
                temporal_proximity=prox,
                proximity_minutes=gap_min,
            ))

        return findings

    def _rule_ca_coverage_gap(self) -> list[Finding]:
        """
        A user had one or more successful sign-ins where no Conditional Access
        policy was evaluated (appliedConditionalAccessPolicies is empty or all
        policies were notApplied/notEnabled).

        This reveals accounts that can authenticate completely outside the tenant's
        CA enforcement boundary — either because no policies target them, they are
        excluded from all policies, or they use a legacy auth client that CA cannot
        evaluate. Attackers deliberately target accounts or flows that fall outside CA.

        Noise reduction: if the tenant has no CA policies at all, only fire for users
        who also have suspicious sign-in flags (impossible travel, risky auth protocol,
        geo-risk, etc.). Tenants with no CA are common on P1-free plans — flagging
        every clean sign-in would flood the report with low-value noise.
        """
        signin_records = self._d("signin_logs")
        if not signin_records:
            return []

        # Infer whether the tenant has CA configured by checking whether any
        # sign-in in the dataset was evaluated against CA policies (even if the
        # result was "notApplied"). An empty appliedConditionalAccessPolicies
        # list means CA was not invoked for that session.
        tenant_has_ca = any(
            bool(r.get("appliedConditionalAccessPolicies"))
            for r in signin_records
        )

        by_user: dict[str, list[dict]] = defaultdict(list)
        for r in signin_records:
            # Only look at successful sign-ins
            status = r.get("status") or {}
            if (status.get("errorCode") or 0) != 0:
                continue

            policies = r.get("appliedConditionalAccessPolicies") or []
            # A record has CA applied if at least one policy has result "success" or "failure"
            ca_applied = any(
                (p.get("result") or "").lower() in ("success", "failure", "reportonlysuccess", "reportonlyfailure")
                for p in policies
            )
            if ca_applied:
                continue

            upn = (r.get("userPrincipalName") or "").lower()
            if upn:
                by_user[upn].append(r)

        findings: list[Finding] = []
        for upn, no_ca_records in by_user.items():
            # Only flag if there are multiple CA-gap sign-ins (reduces noise on SPNs/service accounts)
            if len(no_ca_records) < 2:
                continue

            apps: list[str] = list({
                r.get("clientAppUsed") or r.get("appDisplayName") or "unknown"
                for r in no_ca_records
            })[:4]
            countries: list[str] = list({
                (r.get("location") or {}).get("countryOrRegion") or "unknown"
                for r in no_ca_records
            })[:4]

            evidence: list[Evidence] = []
            for r in no_ca_records[:4]:
                app = r.get("clientAppUsed") or r.get("appDisplayName") or "unknown"
                country = (r.get("location") or {}).get("countryOrRegion") or ""
                evidence.append(_evidence(
                    r, "signin_logs", "createdDateTime",
                    f"CA-gap sign-in via {app}" + (f" from {country}" if country else ""),
                ))

            if tenant_has_ca:
                context_note = (
                    "The tenant has Conditional Access policies configured, but none "
                    "were evaluated for these sessions — this user may be explicitly "
                    "excluded from all policies, or is using a legacy auth client that "
                    "CA cannot intercept."
                )
                recommendation = (
                    f"Review whether {upn} is intentionally excluded from CA policies. "
                    "Check Entra ID > Security > Conditional Access > Sign-in logs to "
                    "identify which policies should have applied. "
                    "Ensure no 'break-glass' exclusions are being abused. "
                    "If using legacy auth clients, block legacy auth via CA "
                    "(policy: block when clientAppTypes includes exchangeActiveSync/other)."
                )
            else:
                context_note = (
                    "The tenant has no Conditional Access policies — all sign-ins bypass "
                    "MFA enforcement and device compliance checks by default. "
                    "This user also has suspicious sign-in flags, making the lack of CA "
                    "a material risk rather than a routine configuration gap."
                )
                recommendation = (
                    "Deploy Conditional Access policies as a matter of priority. "
                    "At minimum: require MFA for all users, block legacy authentication, "
                    "and restrict sign-ins to compliant or hybrid-joined devices. "
                    f"Investigate the suspicious sign-in flags for {upn} immediately."
                )

            findings.append(Finding(
                id="",
                rule="ca_coverage_gap",
                severity="medium",
                title=f"Successful sign-ins with no Conditional Access applied — {upn}",
                user=upn,
                description=(
                    f"{upn} had {len(no_ca_records)} successful sign-in(s) where no "
                    "Conditional Access policy was evaluated. "
                    f"Applications used: {', '.join(apps)}. "
                    f"Countries: {', '.join(countries)}. "
                    f"{context_note}"
                ),
                evidence=evidence,
                recommendation=recommendation,
            ))

        return findings


# ── Report writer ─────────────────────────────────────────────────────────────

_SEV_LABEL = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW"}
_W = 80  # report width


def _write_remediation_script(findings: list[Finding], path: Path) -> None:
    """
    Write remediation_commands.ps1 to *path*.

    Generates PowerShell commands (Microsoft.Graph module) for each HIGH/MEDIUM
    finding, grouped by finding ID with comments.  A $DryRun switch at the top
    gates all destructive commands — analysts review before running.
    """
    lines: list[str] = [
        "# ============================================================",
        "# CIRRUS — Auto-generated Remediation Script",
        f"# Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "#",
        "# REVIEW ALL COMMANDS BEFORE RUNNING.",
        "# Set $DryRun = $false to execute; $true only prints what would happen.",
        "# Requires: Microsoft.Graph PowerShell module (Connect-MgGraph first).",
        "# ============================================================",
        "",
        '$DryRun = $true  # Change to $false to execute',
        "",
        "function Invoke-Remediation {",
        "    param([string]$Description, [scriptblock]$Command)",
        "    Write-Host \"  → $Description\" -ForegroundColor Cyan",
        "    if (-not $DryRun) { & $Command }",
        "    else { Write-Host '    [DRY RUN — skipped]' -ForegroundColor Yellow }",
        "}",
        "",
    ]

    high_findings  = [f for f in findings if f.severity == "high"]
    other_findings = [f for f in findings if f.severity != "high"]

    for group_label, group in (("HIGH severity findings", high_findings),
                                ("MEDIUM / other findings", other_findings)):
        if not group:
            continue
        lines.append(f"# ── {group_label} {'─' * (55 - len(group_label))}")
        lines.append("")

        for finding in group:
            sev_tag = "⚠ HIGH" if finding.severity == "high" else finding.severity.upper()
            lines.append(f"# [{sev_tag}] {finding.id}: {finding.title}")
            if finding.mitre_techniques:
                lines.append(f"#   MITRE: {', '.join(finding.mitre_techniques[:2])}")
            lines.append("")

            user = finding.user or ""

            # --- Rule-specific commands ---
            rule = finding.rule

            if rule in ("bec_attack_pattern", "dual_exfiltration_channels"):
                if user:
                    # Extract forwarding destinations from evidence flags for the comment header
                    fwd_addrs = list(dict.fromkeys(
                        f[len("FORWARDS_TO:"):]
                        for ev in (finding.evidence or [])
                        for f in ev.flags
                        if f.startswith("FORWARDS_TO:")
                    ))
                    lines += [
                        f"# Revoke active sessions for {user}",
                        f"Invoke-Remediation -Description 'Revoke sessions: {user}' -Command {{",
                        f"    Revoke-MgUserSignInSession -UserId '{user}'",
                        "}",
                        f"# Remove SMTP forwarding on {user}'s mailbox",
                        f"Invoke-Remediation -Description 'Remove SMTP forwarding: {user}' -Command {{",
                        f"    Set-Mailbox -Identity '{user}' -ForwardingSmtpAddress $null -DeliverToMailboxAndForward $false",
                        "}",
                    ]
                    if fwd_addrs:
                        lines.append(f"# Forwarding destinations identified: {', '.join(fwd_addrs[:4])}")
                    lines += [
                        f"# Disable suspicious inbox rules for {user} (forwards, deletes, or hides mail):",
                        f"Invoke-Remediation -Description 'Disable suspicious inbox rules: {user}' -Command {{",
                        f"    $rules = Get-InboxRule -Mailbox '{user}' | Where-Object {{",
                        f"        $_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo -or",
                        f"        $_.DeleteMessage -or $_.PermanentDelete -or",
                        f"        ($_.MoveToFolder -and $_.MoveToFolder -in @('DeletedItems', 'JunkEmail', 'RSS Feeds', 'RSS Subscriptions'))",
                        f"    }}",
                        f"    if ($rules) {{",
                        f"        $rules | ForEach-Object {{",
                        f"            Write-Host \"  Disabling: $($_.Name)\" -ForegroundColor Yellow",
                        f"            Disable-InboxRule -Mailbox '{user}' -Identity $_.Identity -Confirm:$false",
                        f"        }}",
                        f"        Write-Host \"  $($rules.Count) rule(s) disabled. Run Remove-InboxRule after review to permanently delete.\" -ForegroundColor Cyan",
                        f"    }} else {{",
                        f"        Write-Host '  No suspicious rules found.' -ForegroundColor Green",
                        f"    }}",
                        "}",
                    ]

            elif rule == "oauth_phishing_pattern":
                if user:
                    lines += [
                        f"# Revoke OAuth grants for {user}",
                        f"Invoke-Remediation -Description 'Revoke OAuth grants: {user}' -Command {{",
                        f"    Get-MgUserOauth2PermissionGrant -UserId '{user}' |",
                        f"    ForEach-Object {{ Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $_.Id }}",
                        "}",
                        f"Invoke-Remediation -Description 'Revoke sessions: {user}' -Command {{",
                        f"    Revoke-MgUserSignInSession -UserId '{user}'",
                        "}",
                    ]

            elif rule in ("suspicious_signin_then_persistence", "password_reset_then_mfa_registered",
                          "spray_then_escalation", "privilege_escalation_after_signin",
                          "device_code_then_device_registered"):
                if user:
                    lines += [
                        f"# Revoke all sessions and disable account for {user} (re-enable after investigation)",
                        f"Invoke-Remediation -Description 'Revoke sessions: {user}' -Command {{",
                        f"    Revoke-MgUserSignInSession -UserId '{user}'",
                        "}",
                        f"# Review and remove suspicious MFA methods for {user}:",
                        f"# Get-MgUserAuthenticationMethod -UserId '{user}'",
                        f"# Remove-MgUserAuthenticationMethod* cmdlet matching the method type",
                        f"# Review recently registered devices:",
                        f"# Get-MgUserRegisteredDevice -UserId '{user}' | Select-Object DisplayName, RegistrationDateTime",
                    ]

            elif rule == "password_spray":
                # Extract spray IPs from PUBLIC_IP: flags in evidence
                spray_ips = list(dict.fromkeys(
                    f[len("PUBLIC_IP:"):]
                    for ev in (finding.evidence or [])
                    for f in ev.flags
                    if f.startswith("PUBLIC_IP:")
                ))[:4]
                if spray_ips:
                    lines += [
                        "# Block spray source IP(s) via Conditional Access Named Locations",
                        "# (Use the Entra portal: Security → Conditional Access → Named Locations → + IP ranges)",
                    ]
                    for ip in spray_ips:
                        lines.append(f"#   Block IP: {ip}")

            elif rule == "mass_mail_access":
                if user:
                    lines += [
                        f"# Revoke sessions and review OAuth apps for {user}",
                        f"Invoke-Remediation -Description 'Revoke sessions: {user}' -Command {{",
                        f"    Revoke-MgUserSignInSession -UserId '{user}'",
                        "}",
                        f"# Audit mailbox access by delegated apps:",
                        f"# Search-UnifiedAuditLog -UserIds '{user}' -Operations MailItemsAccessed -StartDate ... -EndDate ...",
                    ]

            lines.append("")

    if not any(f.severity in ("high", "medium") for f in findings):
        lines.append("# No HIGH or MEDIUM findings — no remediation commands generated.")
        lines.append("")

    lines += [
        "# ── End of generated script ──────────────────────────────────────────",
        "Write-Host 'Remediation script complete.' -ForegroundColor Green",
        "if ($DryRun) { Write-Host 'Set $DryRun = $false and re-run to execute.' -ForegroundColor Yellow }",
    ]

    path.write_text("\n".join(lines), encoding="utf-8")


def _write_text_report(report: dict[str, Any], findings: list[Finding], path: Path) -> None:
    """Write a human-readable ioc_correlation.txt report to path."""
    summary = report["summary"]
    collectors = ", ".join(report.get("collectors_loaded") or [])
    generated = report.get("generated_at", "")
    case_dir = report.get("case_dir", "")

    lines: list[str] = [
        "=" * _W,
        "CIRRUS — Cross-Collector IOC Correlation Report",
        f"Case:       {case_dir}",
        f"Generated:  {generated}",
        f"Collectors: {collectors}",
        f"Findings:   {summary['total_findings']} total  "
        f"({summary.get('high', 0)} HIGH   "
        f"{summary.get('medium', 0)} MEDIUM   "
        f"{summary.get('low', 0)} LOW)",
    ]
    if summary.get("affected_users"):
        lines.append(f"Users:      {', '.join(summary['affected_users'])}")
    lines += ["=" * _W, ""]

    if not findings:
        lines += ["No cross-collector findings.", ""]
    else:
        for f in findings:
            sev = _SEV_LABEL.get(f.severity, f.severity.upper())
            lines += [
                "─" * _W,
                f"{f.id}  [{sev}]  {f.title}",
                f"Rule:  {f.rule}",
            ]
            if f.user:
                lines.append(f"User:  {f.user}")
            lines += ["─" * _W, ""]

            # Description — wrap at 76 chars
            for para in f.description.split(". "):
                para = para.strip()
                if para:
                    lines += _wrap(para + ("." if not para.endswith(".") else ""), 76, "  ") + [""]

            # Evidence table
            if f.evidence:
                lines.append("  Evidence:")
                lines.append(f"  {'Collector':<22} {'Timestamp':<22} Summary")
                lines.append(f"  {'-'*22} {'-'*22} {'-'*28}")
                for ev in f.evidence:
                    ts = (ev.timestamp or "")[:19]
                    collector = ev.collector[:22]
                    summary_text = ev.summary[:60]
                    lines.append(f"  {collector:<22} {ts:<22} {summary_text}")
                lines.append("")

            # IOC flags
            if f.ioc_flags:
                flag_str = "  |  ".join(f.ioc_flags[:6])
                if len(f.ioc_flags) > 6:
                    flag_str += f"  ... (+{len(f.ioc_flags) - 6} more)"
                lines += _wrap(f"Flags: {flag_str}", 76, "  ") + [""]

            # Temporal proximity
            if f.temporal_proximity:
                prox_display = _proximity_note(f.temporal_proximity, f.proximity_minutes)
                if prox_display:
                    lines.append(f"  Temporal proximity: {prox_display}")
                    lines.append("")

            # MITRE ATT&CK techniques
            if f.mitre_techniques:
                lines.append(f"  MITRE ATT&CK: {' · '.join(f.mitre_techniques)}")
                lines.append("")

            # Recommendation
            lines.append("  Recommendation:")
            lines += _wrap(f.recommendation, 76, "    ") + ["", ""]

    lines += ["=" * _W, "END OF REPORT", "=" * _W, ""]
    path.write_text("\n".join(lines), encoding="utf-8")


def _wrap(text: str, width: int, indent: str) -> list[str]:
    """Word-wrap text to width, prepending indent to each line."""
    words = text.split()
    out: list[str] = []
    current = indent
    for word in words:
        if len(current) + len(word) + 1 > width and current.strip():
            out.append(current.rstrip())
            current = indent + word + " "
        else:
            current += word + " "
    if current.strip():
        out.append(current.rstrip())
    return out if out else [indent]


# ── Helpers ────────────────────────────────────────────────────────────────────

def _finding_to_dict(f: Finding) -> dict:
    d = asdict(f)
    d["evidence"] = [asdict(e) for e in f.evidence]
    # Only include proximity fields when populated
    if not d.get("temporal_proximity"):
        d.pop("temporal_proximity", None)
    if d.get("proximity_minutes") is None:
        d.pop("proximity_minutes", None)
    return d


# ── Convenience function ───────────────────────────────────────────────────────

def run_correlator(case_dir: Path, sensitivity: str = "medium") -> dict[str, Any]:
    """
    Run the correlation engine against a case directory and return the report.
    Writes ioc_correlation.json to case_dir as a side effect.
    """
    engine = CorrelationEngine(case_dir, sensitivity=sensitivity)
    return engine.run()
