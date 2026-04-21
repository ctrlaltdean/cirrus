"""
YAML-Based Custom Correlation Rules

Allows analysts to define their own cross-collector correlation rules in YAML
without modifying Python code.  Rule files are loaded from the case directory
or a user-specified path.

Each rule matches records across one or more collectors by IOC flag prefix,
then produces a Finding if records from all required collectors are found
for the same user (or globally if no user key is specified).

Example rule file (custom_rules.yaml):
───────────────────────────────────────
rules:
  - name: oauth_and_forwarding
    title: "OAuth grant with mailbox forwarding"
    severity: high
    description: >
      User has a high-risk OAuth grant AND external mail forwarding.
      This indicates belt-and-suspenders exfiltration.
    recommendation: "Revoke the OAuth grant and disable forwarding."
    match:
      - collector: oauth_grants
        flag_prefix: "HIGH_RISK_SCOPE:"
        user_key: "_sourceUser"
      - collector: mail_forwarding
        flag_prefix: "EXTERNAL_SMTP_FORWARD:"
        user_key: "_sourceUser"

  - name: new_account_with_admin_role
    title: "Newly created account assigned admin role"
    severity: high
    description: >
      An account created during the window was also assigned a high-priv role.
    recommendation: "Verify the account creation was authorized."
    match:
      - collector: users
        flag_prefix: "RECENTLY_CREATED"
        user_key: "userPrincipalName"
      - collector: audit_logs
        flag_prefix: "HIGH_PRIV_ROLE_ASSIGNED:"
        # Uses _targetUser extracted by the correlator
───────────────────────────────────────

Match semantics:
  - Each match clause selects records from a collector that have a flag
    starting with the given prefix.
  - If user_key is specified, the rule groups matches by user UPN.
    A finding fires when the same user appears in ALL match clauses.
  - If no user_key is given on any clause, the rule fires globally
    (all clauses must have at least one matching record).
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

from cirrus.analysis.correlator import Evidence, Finding, _flags, _parse_dt


def load_custom_rules(path: Path) -> list[dict]:
    """
    Load custom correlation rules from a YAML file.

    Returns a list of rule dicts, or an empty list if the file doesn't
    exist or PyYAML is not installed.
    """
    if not path.exists():
        return []
    try:
        import yaml
    except ImportError:
        return []

    try:
        with path.open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if not isinstance(data, dict):
            return []
        rules = data.get("rules") or []
        return [r for r in rules if isinstance(r, dict) and "name" in r and "match" in r]
    except Exception:
        return []


def run_custom_rules(
    rules: list[dict],
    data: dict[str, list[dict]],
) -> list[Finding]:
    """
    Evaluate custom YAML rules against loaded collector data.

    Args:
        rules:  List of parsed rule dicts (from load_custom_rules).
        data:   Dict mapping collector key -> list of records.

    Returns list of Findings for rules that matched.
    """
    findings: list[Finding] = []

    for rule in rules:
        name = rule.get("name", "custom_rule")
        title = rule.get("title", name)
        severity = rule.get("severity", "medium")
        description = rule.get("description", "")
        recommendation = rule.get("recommendation", "")
        match_clauses = rule.get("match") or []

        if not match_clauses:
            continue

        # Determine if this is a per-user rule (any clause has user_key)
        has_user_key = any(c.get("user_key") for c in match_clauses)

        if has_user_key:
            _eval_per_user_rule(
                findings, name, title, severity, description,
                recommendation, match_clauses, data,
            )
        else:
            _eval_global_rule(
                findings, name, title, severity, description,
                recommendation, match_clauses, data,
            )

    return findings


def _eval_per_user_rule(
    findings: list[Finding],
    name: str,
    title: str,
    severity: str,
    description: str,
    recommendation: str,
    clauses: list[dict],
    data: dict[str, list[dict]],
) -> None:
    """Evaluate a rule that correlates across collectors by user."""
    # For each clause, build user -> matching records
    clause_matches: list[dict[str, list[dict]]] = []

    for clause in clauses:
        collector = clause.get("collector", "")
        prefix = clause.get("flag_prefix", "")
        user_key = clause.get("user_key", "_sourceUser")
        records = data.get(collector) or []

        by_user: dict[str, list[dict]] = defaultdict(list)
        for r in records:
            if not prefix or any(f.startswith(prefix) for f in _flags(r)):
                upn = (r.get(user_key) or "").lower()
                if upn and "@" in upn:
                    by_user[upn].append(r)
        clause_matches.append(by_user)

    if not clause_matches:
        return

    # Find users that appear in ALL clauses
    common_users = set(clause_matches[0].keys())
    for cm in clause_matches[1:]:
        common_users &= set(cm.keys())

    for upn in sorted(common_users):
        evidence: list[Evidence] = []
        for clause, cm in zip(clauses, clause_matches):
            collector = clause.get("collector", "")
            for r in cm[upn][:3]:
                ts = r.get("createdDateTime") or r.get("activityDateTime") or ""
                matched_flags = [
                    f for f in _flags(r)
                    if f.startswith(clause.get("flag_prefix", ""))
                ]
                evidence.append(Evidence(
                    collector=collector,
                    timestamp=ts,
                    summary=", ".join(matched_flags[:3]) or collector,
                    flags=_flags(r),
                ))

        findings.append(Finding(
            id="",
            rule=f"custom:{name}",
            severity=severity,
            title=title,
            user=upn,
            description=description.strip(),
            evidence=evidence,
            recommendation=recommendation.strip(),
        ))


def _eval_global_rule(
    findings: list[Finding],
    name: str,
    title: str,
    severity: str,
    description: str,
    recommendation: str,
    clauses: list[dict],
    data: dict[str, list[dict]],
) -> None:
    """Evaluate a global rule (no per-user grouping)."""
    all_matched = True
    evidence: list[Evidence] = []

    for clause in clauses:
        collector = clause.get("collector", "")
        prefix = clause.get("flag_prefix", "")
        records = data.get(collector) or []

        matching = [
            r for r in records
            if not prefix or any(f.startswith(prefix) for f in _flags(r))
        ]
        if not matching:
            all_matched = False
            break

        for r in matching[:3]:
            ts = r.get("createdDateTime") or r.get("activityDateTime") or ""
            matched_flags = [
                f for f in _flags(r)
                if f.startswith(prefix)
            ]
            evidence.append(Evidence(
                collector=collector,
                timestamp=ts,
                summary=", ".join(matched_flags[:3]) or collector,
                flags=_flags(r),
            ))

    if all_matched and evidence:
        findings.append(Finding(
            id="",
            rule=f"custom:{name}",
            severity=severity,
            title=title,
            user="",
            description=description.strip(),
            evidence=evidence,
            recommendation=recommendation.strip(),
        ))
