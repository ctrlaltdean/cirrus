"""
Workflow: Service Principal Compromise Investigation

Focused investigation for compromised OAuth apps and service principals.
Use when you have evidence of OAuth phishing, a client secret has leaked,
or a service principal is exhibiting anomalous sign-in behaviour.

Attack patterns covered:
  OAuth phishing   — attacker tricks user into consenting a malicious app that
                     gets persistent Mail.Read / Files.ReadWrite.All access
  Client secret    — attacker extracts a secret from source code or Key Vault
                     and uses it to authenticate AS the app from their own infra
  Rogue app        — attacker registers a new app in the tenant as a backdoor;
                     the app may have no owner and can be long-lived

Collection order:
  1. Service principals     — inventory of all apps; flags orphaned / unverified
  2. App registrations      — recently created apps in the tenant
  3. OAuth grants           — what users consented to; surfaces high-risk scopes
  4. SP sign-in logs        — authentication timeline for the app(s); geo anomalies
  5. Users                  — account roster so grants can be attributed
  6. Entra audit logs       — app consent events, secret/cert additions, SP mods
  7. Unified Audit Log      — MailItemsAccessed, file downloads, sharing events
                               performed by the compromised app's tokens

Typical usage:
    cirrus run sp --tenant contoso.com --days 30
    cirrus run sp --tenant contoso.com --app-id <app-id> --days 30
    cirrus run sp --tenant contoso.com --start-date 2026-03-01 --end-date 2026-03-18
"""

from __future__ import annotations

from datetime import datetime

from cirrus.collectors.app_registrations import AppRegistrationsCollector
from cirrus.collectors.audit_logs import AuditLogsCollector
from cirrus.collectors.oauth_grants import OAuthGrantsCollector
from cirrus.collectors.service_principals import ServicePrincipalsCollector
from cirrus.collectors.sp_signin_logs import SPSignInLogsCollector
from cirrus.collectors.unified_audit import POLL_TIMEOUT, UnifiedAuditCollector
from cirrus.collectors.users import UsersCollector
from cirrus.workflows.base import BaseWorkflow


class SPCompromiseWorkflow(BaseWorkflow):
    name = "sp"
    description = "Service principal / OAuth app compromise investigation"

    def _build_steps(
        self,
        users: list[str] | None,
        start_dt: datetime,
        end_dt: datetime,
        **kwargs,
    ) -> list[tuple]:
        app_ids: list[str] | None = kwargs.get("app_ids") or None

        return [
            (
                ServicePrincipalsCollector,
                {"days": None},
                "Service principals (all apps)",
            ),
            (
                AppRegistrationsCollector,
                {"start_dt": start_dt, "end_dt": end_dt},
                "App registrations (recent)",
            ),
            (
                OAuthGrantsCollector,
                {"users": users},
                "OAuth grants",
            ),
            (
                SPSignInLogsCollector,
                {
                    "start_dt": start_dt,
                    "end_dt": end_dt,
                    **({"app_ids": app_ids} if app_ids else {}),
                },
                "Service principal sign-in logs",
            ),
            (
                UsersCollector,
                {"users": users, "start_dt": start_dt},
                "User directory (consent attribution)",
            ),
            (
                AuditLogsCollector,
                {"users": users, "start_dt": start_dt, "end_dt": end_dt},
                "Entra audit logs (consent & SP events)",
            ),
            (
                UnifiedAuditCollector,
                {
                    "users": users,
                    "start_dt": start_dt,
                    "end_dt": end_dt,
                    "poll_timeout": kwargs.get("ual_timeout", POLL_TIMEOUT),
                },
                "Unified Audit Log (app-token operations)",
            ),
        ]
