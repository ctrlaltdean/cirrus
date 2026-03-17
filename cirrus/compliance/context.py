"""
PolicyContext: pre-fetches all data needed by compliance checks in one pass.

Doing this upfront means checks inspect local dicts instead of each
making their own API calls — fewer round trips and consistent snapshots.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import requests

from cirrus.collectors.base import GRAPH_BASE, GRAPH_BETA, GraphCollector


@dataclass
class PolicyContext:
    """All tenant policy data needed to run compliance checks."""

    # Entra / Identity policies
    security_defaults: dict = field(default_factory=dict)
    authorization_policy: dict = field(default_factory=dict)
    ca_policies: list[dict] = field(default_factory=list)
    admin_consent_policy: dict = field(default_factory=dict)
    auth_methods_policy: dict = field(default_factory=dict)

    # Organization
    organization: dict = field(default_factory=dict)
    subscribed_skus: list[dict] = field(default_factory=list)

    # Directory (admin roles, users)
    global_admins: list[dict] = field(default_factory=list)
    privileged_role_members: dict[str, list[dict]] = field(default_factory=dict)

    # Security / Secure Score
    secure_score: dict = field(default_factory=dict)
    secure_score_profiles: list[dict] = field(default_factory=list)

    # Errors encountered during pre-fetch (non-fatal)
    fetch_errors: dict[str, str] = field(default_factory=dict)


class ContextBuilder(GraphCollector):
    """Fetches and assembles a PolicyContext from the Graph API."""

    name = "policy_context"

    # Well-known role template IDs
    GLOBAL_ADMIN_ROLE_ID = "62e90394-69f5-4237-9190-012177145e10"
    PRIVILEGED_ROLE_ADMIN_ID = "e8611ab8-c189-46e8-94e1-60213ab1f814"
    SECURITY_ADMIN_ID = "194ae4cb-b126-40b2-bd5b-6091b380977d"
    EXCHANGE_ADMIN_ID = "29232cdf-9323-42fd-ade2-1d097af3e4de"
    SHAREPOINT_ADMIN_ID = "f28a1f50-f6e7-4571-818b-6a12f2af6b6c"
    TEAMS_ADMIN_ID = "69091246-20e8-4a56-aa4d-066075b2a7a8"

    WATCHED_ROLES = {
        "Global Administrator": GLOBAL_ADMIN_ROLE_ID,
        "Privileged Role Administrator": PRIVILEGED_ROLE_ADMIN_ID,
        "Security Administrator": SECURITY_ADMIN_ID,
        "Exchange Administrator": EXCHANGE_ADMIN_ID,
        "SharePoint Administrator": SHAREPOINT_ADMIN_ID,
        "Teams Administrator": TEAMS_ADMIN_ID,
    }

    def build(self) -> PolicyContext:
        ctx = PolicyContext()

        # --- Identity Security Defaults ---
        try:
            ctx.security_defaults = self._get(
                f"{GRAPH_BASE}/policies/identitySecurityDefaultsEnforcementPolicy"
            )
        except Exception as e:
            ctx.fetch_errors["security_defaults"] = str(e)

        # --- Authorization Policy ---
        try:
            data = self._get(f"{GRAPH_BASE}/policies/authorizationPolicy")
            # authorizationPolicy returns an array wrapper in some tenants
            if "value" in data:
                ctx.authorization_policy = data["value"][0] if data["value"] else {}
            else:
                ctx.authorization_policy = data
        except Exception as e:
            ctx.fetch_errors["authorization_policy"] = str(e)

        # --- Conditional Access Policies ---
        try:
            ctx.ca_policies = self._collect_all(
                f"{GRAPH_BASE}/identity/conditionalAccess/policies",
                params={"$top": 999},
            )
        except Exception as e:
            ctx.fetch_errors["ca_policies"] = str(e)

        # --- Admin Consent Request Policy ---
        try:
            ctx.admin_consent_policy = self._get(
                f"{GRAPH_BASE}/policies/adminConsentRequestPolicy"
            )
        except Exception as e:
            ctx.fetch_errors["admin_consent_policy"] = str(e)

        # --- Authentication Methods Policy ---
        try:
            ctx.auth_methods_policy = self._get(
                f"{GRAPH_BASE}/policies/authenticationMethodsPolicy"
            )
        except Exception as e:
            ctx.fetch_errors["auth_methods_policy"] = str(e)

        # --- Organization ---
        try:
            orgs = self._collect_all(
                f"{GRAPH_BASE}/organization",
                params={"$select": "id,displayName,passwordPolicies,onPremisesSyncEnabled,assignedPlans,provisionedPlans"},
            )
            ctx.organization = orgs[0] if orgs else {}
        except Exception as e:
            ctx.fetch_errors["organization"] = str(e)

        # --- Subscribed SKUs (license info) ---
        try:
            ctx.subscribed_skus = self._collect_all(
                f"{GRAPH_BASE}/subscribedSkus",
                params={"$select": "skuPartNumber,skuId,capabilityStatus,servicePlans"},
            )
        except Exception as e:
            ctx.fetch_errors["subscribed_skus"] = str(e)

        # --- Directory Roles and Members ---
        try:
            all_roles = self._collect_all(f"{GRAPH_BASE}/directoryRoles")
            for role in all_roles:
                role_name = role.get("displayName", "")
                role_id = role.get("id", "")
                template_id = role.get("roleTemplateId", "")
                if template_id in self.WATCHED_ROLES.values() or role_name in self.WATCHED_ROLES:
                    try:
                        members = self._collect_all(
                            f"{GRAPH_BASE}/directoryRoles/{role_id}/members",
                            params={"$select": "id,displayName,userPrincipalName,onPremisesSyncEnabled,userType"},
                        )
                        ctx.privileged_role_members[role_name] = members
                        if template_id == self.GLOBAL_ADMIN_ROLE_ID or role_name == "Global Administrator":
                            ctx.global_admins = members
                    except Exception:
                        pass
        except Exception as e:
            ctx.fetch_errors["directory_roles"] = str(e)

        # --- Secure Score (latest) ---
        try:
            scores = self._collect_all(
                f"{GRAPH_BASE}/security/secureScores",
                params={"$top": 1},
            )
            ctx.secure_score = scores[0] if scores else {}
        except Exception as e:
            ctx.fetch_errors["secure_score"] = str(e)

        # --- Secure Score Control Profiles ---
        try:
            ctx.secure_score_profiles = self._collect_all(
                f"{GRAPH_BASE}/security/secureScoreControlProfiles",
                params={"$top": 999},
            )
        except Exception as e:
            ctx.fetch_errors["secure_score_profiles"] = str(e)

        return ctx
