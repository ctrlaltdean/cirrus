"""
CIS Compliance Checks — Section 2: M365 Administration

Covers: Admin account hygiene, global admin count, cloud-only admins,
        Defender for Office 365 licensing, Microsoft Secure Score.
"""

from __future__ import annotations

from cirrus.compliance.base import BaseCheck, CheckResult, CheckStatus
from cirrus.compliance.context import PolicyContext

# Service plan IDs for Defender for Office 365
DEFENDER_P1_PLAN = "9f431833-0334-42de-a7dc-70aa40db46db"
DEFENDER_P2_PLAN = "bed136c6-b799-4462-824d-fc045d3a9d25"
EOP_PLAN = "82bcec0d-dc35-4b3f-b78d-b5702e4705bf"  # Exchange Online Protection (baseline)


def _has_service_plan(subscribed_skus: list[dict], plan_id: str) -> bool:
    for sku in subscribed_skus:
        for plan in sku.get("servicePlans", []):
            if plan.get("servicePlanId", "").lower() == plan_id.lower():
                if plan.get("provisioningStatus", "").lower() == "success":
                    return True
    return False


# ---------------------------------------------------------------------------
# 2.1 — Admin Account Hygiene
# ---------------------------------------------------------------------------

class CheckGlobalAdminCount(BaseCheck):
    """
    M365-2.1.1
    Ensure between 2 and 4 Global Administrators are designated.
    Too few = single point of failure. Too many = excessive attack surface.
    """
    control_id = "M365-2.1.1"
    title = "Global Administrator count (2–4 recommended)"
    benchmark = "CIS M365"
    level = 1
    section = "2 - M365 Administration"
    rationale = (
        "A single global admin is a single point of failure. "
        "More than 4 global admins creates unnecessary privileged attack surface."
    )
    remediation = (
        "Review global administrator assignments in Entra ID > Roles and administrators > "
        "Global Administrator. Use Privileged Identity Management (PIM) for just-in-time access."
    )
    reference = "CIS M365 v3.1 §2.1.1"

    def run(self, ctx: PolicyContext) -> CheckResult:
        count = len(ctx.global_admins)
        if count == 0:
            return self._result(
                CheckStatus.ERROR,
                expected="2–4 global admins",
                actual="0 global admins found (API error or empty role)",
                notes="Could not retrieve global admin members.",
            )
        if count == 1:
            return self._result(
                CheckStatus.FAIL,
                expected="2–4 global admins",
                actual=f"{count} global admin (single point of failure)",
            )
        if count > 4:
            names = ", ".join(a.get("userPrincipalName", a.get("displayName", "?")) for a in ctx.global_admins)
            return self._result(
                CheckStatus.FAIL,
                expected="2–4 global admins",
                actual=f"{count} global admins: {names}",
                notes="Reduce to 4 or fewer. Use PIM for just-in-time elevation.",
            )
        names = ", ".join(a.get("userPrincipalName", a.get("displayName", "?")) for a in ctx.global_admins)
        return self._result(
            CheckStatus.PASS,
            expected="2–4 global admins",
            actual=f"{count} global admins: {names}",
        )


class CheckAdminsCloudOnly(BaseCheck):
    """
    M365-2.1.2
    Ensure privileged admin accounts are cloud-only (not synced from on-premises AD).
    """
    control_id = "M365-2.1.2"
    title = "Admin accounts are cloud-only (not on-prem synced)"
    benchmark = "CIS M365"
    level = 1
    section = "2 - M365 Administration"
    rationale = (
        "Admin accounts synced from on-prem AD inherit vulnerabilities from the on-prem environment. "
        "A compromised on-prem AD can lead to cloud admin takeover."
    )
    remediation = (
        "Create dedicated cloud-only admin accounts. Remove admin roles from "
        "on-premises synced accounts. Admin accounts should not be used for email."
    )
    reference = "CIS M365 v3.1 §2.1.2"

    def run(self, ctx: PolicyContext) -> CheckResult:
        if not ctx.global_admins:
            return self._result(
                CheckStatus.ERROR,
                expected="All admin accounts cloud-only",
                actual="Could not retrieve global admin list",
                notes="",
            )

        synced_admins = [
            a for a in ctx.global_admins
            if a.get("onPremisesSyncEnabled") is True
        ]

        if synced_admins:
            names = ", ".join(
                a.get("userPrincipalName", a.get("displayName", "?"))
                for a in synced_admins
            )
            return self._result(
                CheckStatus.FAIL,
                expected="All admin accounts cloud-only",
                actual=f"{len(synced_admins)} on-prem synced admin(s): {names}",
            )

        return self._result(
            CheckStatus.PASS,
            expected="All admin accounts cloud-only",
            actual=f"All {len(ctx.global_admins)} global admin(s) are cloud-only",
        )


class CheckPrivilegedRoleAdminCount(BaseCheck):
    """
    M365-2.1.3
    Ensure no unnecessary accounts hold Privileged Role Administrator.
    This is the role that can assign ALL other roles — its own tier-0.
    """
    control_id = "M365-2.1.3"
    title = "Privileged Role Administrator minimized"
    benchmark = "CIS M365 & Entra"
    level = 2
    section = "2 - M365 Administration"
    rationale = "Privileged Role Administrator can grant any role to any account, including Global Admin. It should be held by very few accounts."
    remediation = "Review accounts in the Privileged Role Administrator role. Reduce to minimum required. Use PIM for just-in-time access."
    reference = "CIS Entra v2.0 §2.2"

    def run(self, ctx: PolicyContext) -> CheckResult:
        members = ctx.privileged_role_members.get("Privileged Role Administrator", [])

        if not members:
            return self._result(
                CheckStatus.PASS,
                expected="Minimal Privileged Role Administrator membership",
                actual="No members found in Privileged Role Administrator role",
                notes="If this role has members that were not retrieved, verify manually.",
            )

        if len(members) > 2:
            names = ", ".join(
                m.get("userPrincipalName", m.get("displayName", "?"))
                for m in members
            )
            return self._result(
                CheckStatus.FAIL,
                expected="≤2 members in Privileged Role Administrator",
                actual=f"{len(members)} members: {names}",
            )

        names = ", ".join(
            m.get("userPrincipalName", m.get("displayName", "?"))
            for m in members
        )
        return self._result(
            CheckStatus.PASS,
            expected="≤2 members in Privileged Role Administrator",
            actual=f"{len(members)} member(s): {names}",
        )


# ---------------------------------------------------------------------------
# 2.2 — Microsoft 365 Defender Licensing
# ---------------------------------------------------------------------------

class CheckDefenderForOffice365(BaseCheck):
    """
    M365-2.2.1
    Ensure Microsoft Defender for Office 365 Plan 1 or 2 is licensed.
    """
    control_id = "M365-2.2.1"
    title = "Microsoft Defender for Office 365 licensed"
    benchmark = "CIS M365"
    level = 2
    section = "2 - M365 Administration"
    rationale = "Defender for Office 365 provides Safe Links, Safe Attachments, anti-phishing protection beyond EOP baseline."
    remediation = "Purchase Microsoft Defender for Office 365 Plan 1 (minimum) or Plan 2."
    reference = "CIS M365 v3.1 §2.2"

    def run(self, ctx: PolicyContext) -> CheckResult:
        has_p2 = _has_service_plan(ctx.subscribed_skus, DEFENDER_P2_PLAN)
        has_p1 = _has_service_plan(ctx.subscribed_skus, DEFENDER_P1_PLAN)

        if has_p2:
            return self._result(
                CheckStatus.PASS,
                expected="Defender for Office 365 P1 or P2",
                actual="Defender for Office 365 Plan 2 licensed",
            )
        if has_p1:
            return self._result(
                CheckStatus.PASS,
                expected="Defender for Office 365 P1 or P2",
                actual="Defender for Office 365 Plan 1 licensed",
            )
        return self._result(
            CheckStatus.FAIL,
            expected="Defender for Office 365 Plan 1 or Plan 2",
            actual="Defender for Office 365 not found in subscribed SKUs",
            notes="EOP (Exchange Online Protection) is included but does not provide Safe Links or Safe Attachments.",
        )


# ---------------------------------------------------------------------------
# 2.3 — Microsoft Secure Score (informational)
# ---------------------------------------------------------------------------

class CheckSecureScore(BaseCheck):
    """
    M365-2.3.1 (informational)
    Report the tenant's current Microsoft Secure Score and percentage.
    Not a pass/fail — displayed as an informational WARN to prompt review.
    """
    control_id = "M365-2.3.1"
    title = "Microsoft Secure Score"
    benchmark = "CIS M365"
    level = 1
    section = "2 - M365 Administration"
    rationale = "Microsoft Secure Score provides a holistic view of the tenant's security posture against Microsoft's recommended controls."
    remediation = "Review the Secure Score dashboard in the Microsoft Defender portal and address high-impact improvement actions."
    reference = "Microsoft Security documentation"

    def run(self, ctx: PolicyContext) -> CheckResult:
        score = ctx.secure_score
        if not score:
            return self._result(
                CheckStatus.ERROR,
                expected="Secure Score available",
                actual="Could not retrieve Secure Score",
            )

        current = score.get("currentScore", 0)
        max_score = score.get("maxScore", 0)
        pct = round((current / max_score * 100), 1) if max_score else 0

        status = CheckStatus.PASS if pct >= 70 else (CheckStatus.WARN if pct >= 40 else CheckStatus.FAIL)

        return self._result(
            status,
            expected="≥70% of max Secure Score",
            actual=f"{current}/{max_score} ({pct}%)",
            notes="Review Microsoft Defender portal > Secure Score for specific improvement actions.",
        )


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

ADMIN_CHECKS: list[type[BaseCheck]] = [
    CheckGlobalAdminCount,
    CheckAdminsCloudOnly,
    CheckPrivilegedRoleAdminCount,
    CheckDefenderForOffice365,
    CheckSecureScore,
]
