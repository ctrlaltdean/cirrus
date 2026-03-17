"""
Tenant license profile.

Fetches the tenant's subscribed SKUs once and exposes boolean flags that
collectors use to decide whether a Graph API endpoint is available on the
current tenant.  The profile is fetched once per workflow run and injected
into every collector so that no redundant API calls are made.

Collectors that run standalone (outside a workflow) perform a lazy fetch on
the first _require_license() call and cache the result on the instance.
"""

from __future__ import annotations

from dataclasses import dataclass

import requests

_GRAPH_BASE = "https://graph.microsoft.com/v1.0"

# Service plan GUIDs that gate specific CIRRUS features.
# P2 implies P1 — any P2 SKU also has P1 activated.
_PLAN_ID = {
    "entra_p1":          "41781fb2-bc02-4b7c-bd55-b576c07bb09d",
    "entra_p2":          "eec0eb4f-6444-4f95-aba0-50c24d67f998",
    "exchange_p1":       "9aaf7827-d63c-4b61-89c3-182f06f82e5c",
    "exchange_p2":       "efb87545-963c-4e0d-99df-69c6916d9eb0",
    "advanced_auditing": "2f442157-a11c-46b9-ae5b-6e39ff4e5849",
}

# Display labels for the pre-run summary banner
_LABEL = {
    "p1":               "Entra ID P1",
    "p2":               "Entra ID P2",
    "advanced_auditing": "M365 Advanced Auditing (UAL)",
}

# Collector names that each feature gates — shown in the pre-run summary
_GATES = {
    "p1":               ["signin_logs", "entra_audit_logs", "conditional_access_policies"],
    "p2":               ["risky_users", "risky_signins"],
    "advanced_auditing": ["unified_audit_log"],
}


@dataclass
class TenantLicenseProfile:
    """
    Snapshot of which license tiers are active on the tenant.

    Fields
    ------
    has_entra_p1 : bool
        True if Entra ID P1 (or P2, which includes P1) is active.
        Required for: sign-in logs, directory audit logs, Conditional Access.
    has_entra_p2 : bool
        True if Entra ID P2 is active.
        Required for: Identity Protection (riskyUsers, riskySignIns).
    has_exchange : bool
        True if any Exchange Online plan is active.
        Required for: mailbox rules, mail forwarding.
    has_advanced_auditing : bool
        True if M365 Advanced Auditing (Purview / E5) is active.
        Required for: Unified Audit Log (UAL) via beta endpoint.
    """

    has_entra_p1: bool
    has_entra_p2: bool
    has_exchange: bool
    has_advanced_auditing: bool

    # ------------------------------------------------------------------ #
    # Factory                                                              #
    # ------------------------------------------------------------------ #

    @classmethod
    def from_subscribed_skus(cls, skus: list[dict]) -> "TenantLicenseProfile":
        """
        Build a profile from an already-fetched /subscribedSkus list.

        Use this in the compliance layer where SKUs are fetched as part of
        the PolicyContext — avoids a redundant API call.
        """
        active_ids: set[str] = set()
        for sku in skus:
            if sku.get("capabilityStatus", "").lower() != "enabled":
                continue
            for plan in sku.get("servicePlans", []):
                if plan.get("provisioningStatus", "").lower() == "success":
                    active_ids.add(plan.get("servicePlanId", ""))

        p2 = _PLAN_ID["entra_p2"] in active_ids
        exchange = (
            _PLAN_ID["exchange_p1"] in active_ids
            or _PLAN_ID["exchange_p2"] in active_ids
        )

        return cls(
            has_entra_p1=(p2 or _PLAN_ID["entra_p1"] in active_ids),
            has_entra_p2=p2,
            has_exchange=exchange,
            has_advanced_auditing=(_PLAN_ID["advanced_auditing"] in active_ids),
        )

    @classmethod
    def fetch(cls, session: requests.Session) -> "TenantLicenseProfile":
        """
        Query /subscribedSkus and build the profile.

        On any failure (network error, 403, etc.) returns a fully-permissive
        profile so that the real API error surfaces from the collector itself
        rather than from the license pre-check.
        """
        try:
            resp = session.get(
                f"{_GRAPH_BASE}/subscribedSkus",
                params={"$select": "servicePlans,capabilityStatus"},
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            return cls._permissive()

        return cls.from_subscribed_skus(data.get("value", []))

    @classmethod
    def _permissive(cls) -> "TenantLicenseProfile":
        """Return a fully-permissive profile (fail-open on SKU check errors)."""
        return cls(
            has_entra_p1=True,
            has_entra_p2=True,
            has_exchange=True,
            has_advanced_auditing=True,
        )

    # ------------------------------------------------------------------ #
    # Query helpers                                                        #
    # ------------------------------------------------------------------ #

    def allows(self, feature: str) -> bool:
        """
        Return True if the named feature is licensed.

        feature must be one of: "p1", "p2", "exchange", "advanced_auditing".
        Unknown feature strings return True (fail-open).
        """
        return {
            "p1":               self.has_entra_p1,
            "p2":               self.has_entra_p2,
            "exchange":         self.has_exchange,
            "advanced_auditing": self.has_advanced_auditing,
        }.get(feature, True)

    # ------------------------------------------------------------------ #
    # Display                                                              #
    # ------------------------------------------------------------------ #

    def summary_rows(self) -> list[tuple[str, bool, list[str]]]:
        """
        Return rows for the pre-run license banner.
        Each row: (label, is_available, [collector_names_that_will_be_skipped]).
        """
        rows = []
        for key in ("p1", "p2", "advanced_auditing"):
            available = self.allows(key)
            skipped = _GATES[key] if not available else []
            rows.append((_LABEL[key], available, skipped))
        return rows
