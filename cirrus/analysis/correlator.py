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

  new_account_with_signin             [MEDIUM]
    A user flagged RECENTLY_CREATED in the users collector who also appears
    in sign-in logs — may indicate an attacker-created backdoor account.

  cross_ip_correlation                [MEDIUM]
    A public IP address that appears in both sign-in logs and directory audit
    logs — suggests the same session or attacker source performed both auth
    and directory changes.
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
}

# Suspicious sign-in flag prefixes that trigger persistence checks
_SUSPICIOUS_SIGNIN_PREFIXES = (
    "SUSPICIOUS_AUTH_PROTOCOL:",
    "IMPOSSIBLE_TRAVEL:",
    "GEO_RISK:",
    "RISK_STATE:atRisk",
    "RISK_STATE:confirmedCompromised",
    "IDENTITY_RISK:",
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
    ioc_flags: list[str] = field(default_factory=list)  # de-duplicated flags from evidence


# ── Helpers ────────────────────────────────────────────────────────────────────

def _parse_dt(ts: str) -> datetime:
    """Parse an ISO-8601 timestamp to UTC-aware datetime, or return epoch on failure."""
    if not ts:
        return datetime.min.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return datetime.min.replace(tzinfo=timezone.utc)


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

    def __init__(self, case_dir: Path) -> None:
        self.case_dir = case_dir
        self._data: dict[str, list[dict]] = {}
        self._loaded: list[str] = []

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
            self._rule_device_code_then_device_registered,
            self._rule_new_account_with_signin,
            self._rule_cross_ip_correlation,
        ]

        for rule_fn in rules:
            try:
                rule_findings = rule_fn()
                for f in rule_findings:
                    f.id = _next_id()
                    f.ioc_flags = _dedup_flags(f.evidence)
                findings.extend(rule_findings)
            except Exception:
                pass  # Never let a broken rule crash the whole workflow

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

        return report

    # ── Data loading ───────────────────────────────────────────────────────────

    def _load(self) -> None:
        for key, filename in _COLLECTOR_FILES.items():
            path = self.case_dir / filename
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
            if upn and _has_flag_prefix(r, "RECENTLY_ADDED", "HIGH_PERSISTENCE_METHOD"):
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
                ),
                evidence=evidence,
                recommendation=(
                    "Verify timestamps — confirm whether the sign-in and registration are causally linked. "
                    "If unauthorized: disable the account, remove the new MFA method or device, "
                    "revoke all active sessions (revokeSignInSessions), and reset credentials."
                ),
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
                ),
                evidence=evidence,
                recommendation=(
                    "Confirm who initiated the password reset — if not part of authorized IR, "
                    "this indicates the attacker had admin-level access. Remove the new MFA method, "
                    "reset the account password again, revoke all sessions, and audit the admin account "
                    "that performed the reset."
                ),
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

            findings.append(Finding(
                id="",
                rule="privilege_escalation_after_signin",
                severity="high",
                title="Suspicious sign-in activity during privilege escalation window",
                user=upn,
                description=(
                    f"{upn} had suspicious sign-in activity and was also granted a high-privilege role "
                    f"({'; '.join(roles_assigned[:3])}) during the same collection window. "
                    "Attackers who gain access often assign themselves admin roles before performing "
                    "further actions or establishing persistence."
                ),
                evidence=evidence,
                recommendation=(
                    "Verify whether the role assignment was authorized. If not, remove the role, "
                    "disable the account, revoke all sessions, and audit all actions taken "
                    "using the elevated privileges (check audit logs for actions after the role assignment)."
                ),
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
                ),
                evidence=evidence,
                recommendation=(
                    "Remove the newly registered device immediately — it may carry a PRT that "
                    "persists after password reset. Revoke all sign-in sessions, reset credentials, "
                    "and verify the device code sign-in was not user-initiated (check with the user). "
                    "Block legacy auth and device code flows via Conditional Access if not already done."
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
                (f for f in _flags(user_rec) if f.startswith("RECENTLY_CREATED")),
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

            findings.append(Finding(
                id="",
                rule="new_account_with_signin",
                severity="medium",
                title="Recently created account with active sign-in activity",
                user=upn,
                description=(
                    f"{upn} was created recently ({created_flag}) and already has "
                    f"{len(signins)} sign-in event(s) in the collection window. "
                    "Attackers create backdoor accounts that authenticate quickly after creation. "
                    "Verify this account was created through authorized provisioning processes."
                ),
                evidence=evidence,
                recommendation=(
                    "Verify the account creation was authorized (check audit logs for the USER_CREATED event "
                    "and who initiated it). If unauthorized: disable immediately, revoke all sessions, "
                    "and audit what the account accessed."
                ),
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


# ── Report writer ─────────────────────────────────────────────────────────────

_SEV_LABEL = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW"}
_W = 80  # report width


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
    return d


# ── Convenience function ───────────────────────────────────────────────────────

def run_correlator(case_dir: Path) -> dict[str, Any]:
    """
    Run the correlation engine against a case directory and return the report.
    Writes ioc_correlation.json to case_dir as a side effect.
    """
    engine = CorrelationEngine(case_dir)
    return engine.run()
