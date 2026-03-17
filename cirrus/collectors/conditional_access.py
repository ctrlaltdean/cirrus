"""
Collector: Conditional Access Policies

Endpoint: GET /identity/conditionalAccess/policies
Requires:  Policy.Read.All

Captures the full set of CA policies. During a BEC investigation:
  - Attacker may have disabled or modified CA policies to weaken controls
  - Useful to compare against a known-good baseline
  - Policies in 'reportOnly' mode may indicate recent changes
  - Policies excluding specific users may indicate targeted exceptions

Key IOCs:
  - Policies recently set to 'disabled'
  - Policies excluding the compromised account(s) from MFA requirements
  - Policies with no MFA requirement for external IP ranges
"""

from __future__ import annotations

from cirrus.collectors.base import GRAPH_BASE, GraphCollector


class ConditionalAccessCollector(GraphCollector):
    name = "conditional_access_policies"

    def collect(self, **kwargs) -> list[dict]:
        """
        Collect all Conditional Access policies.
        Returns list of policy dicts annotated with IOC flags.
        """
        self._require_license(
            "p1",
            "Conditional Access policies require Entra ID P1 or higher.",
        )

        policies = self._collect_all(
            f"{GRAPH_BASE}/identity/conditionalAccess/policies",
            params={
                "$select": (
                    "id,displayName,state,createdDateTime,modifiedDateTime,"
                    "conditions,grantControls,sessionControls"
                ),
                "$top": 999,
            },
        )
        for policy in policies:
            policy["_iocFlags"] = _flag_policy(policy)
        return policies


def _flag_policy(policy: dict) -> list[str]:
    flags: list[str] = []
    state = policy.get("state", "").lower()

    if state == "disabled":
        flags.append("POLICY_DISABLED")
    elif state == "enabledforreportingbutnotenforced":
        flags.append("POLICY_REPORT_ONLY")

    grant = policy.get("grantControls") or {}
    built_in = grant.get("builtInControls", [])
    if not built_in or "mfa" not in [c.lower() for c in built_in]:
        operator = grant.get("operator", "")
        if operator:
            flags.append("NO_MFA_REQUIREMENT")

    conditions = policy.get("conditions", {})
    excluded_users = (
        (conditions.get("users") or {}).get("excludeUsers", [])
    )
    if excluded_users:
        flags.append(f"EXCLUDES_USERS:{len(excluded_users)}")

    excluded_groups = (
        (conditions.get("users") or {}).get("excludeGroups", [])
    )
    if excluded_groups:
        flags.append(f"EXCLUDES_GROUPS:{len(excluded_groups)}")

    return flags
