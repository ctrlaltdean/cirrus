"""
Workflow: Account Takeover (ATO) Investigation

Collects the targeted set of artifacts most relevant to an ATO investigation,
in the order that best supports timeline reconstruction and blast-radius
assessment.

ATO vs BEC:
  BEC focuses on what the attacker did *inside* the mailbox after gaining
  access (rules, forwarding, wire fraud). ATO focuses on the authentication
  layer — how did they get in, what did they do with access, and what
  persistence mechanisms did they leave behind.

Collection order (each step informs the next):
  1. Users              — account roster, creation dates, MFA registration status
  2. Sign-in logs       — authentication timeline; IOC flags surface legacy auth,
                          device code phishing, impossible travel, risk signals
  3. Entra audit logs   — directory changes: MFA added, passwords reset, roles
                          assigned, CA policies modified, apps consented
  4. MFA methods        — current registered methods (look for attacker-added
                          phone numbers / authenticator apps)
  5. Risky users        — Microsoft Identity Protection risk scoring (P2)
  6. Risky sign-ins     — Identity Protection risk events (P2)
  7. Conditional Access — what enforcement was in place; explains how entry was
                          possible if CA policies were absent or misconfigured
  8. Registered devices — devices added to target accounts during the window;
                          PRT-bound devices survive password resets
  9. OAuth grants       — app consent grants that persist after credential reset
 10. App registrations  — new apps created in the tenant during the window;
                          a common attacker persistence mechanism
 11. UAL                — what did the attacker access or exfiltrate:
                          MailItemsAccessed, file downloads, sharing events

Typical usage:
    cirrus run ato --tenant contoso.com --user john@contoso.com --days 30
    cirrus run ato --tenant contoso.com --all-users --start-date 2026-03-01 --end-date 2026-03-18
"""

from __future__ import annotations

from datetime import datetime

from cirrus.collectors.app_registrations import AppRegistrationsCollector
from cirrus.collectors.audit_logs import AuditLogsCollector
from cirrus.collectors.conditional_access import ConditionalAccessCollector
from cirrus.collectors.mfa_methods import MFAMethodsCollector
from cirrus.collectors.oauth_grants import OAuthGrantsCollector
from cirrus.collectors.registered_devices import RegisteredDevicesCollector
from cirrus.collectors.risky_users import RiskySignInsCollector, RiskyUsersCollector
from cirrus.collectors.pim_activations import PIMActivationsCollector
from cirrus.collectors.signin_logs import SignInLogsCollector
from cirrus.collectors.sp_signin_logs import SPSignInLogsCollector
from cirrus.collectors.unified_audit import POLL_TIMEOUT, UnifiedAuditCollector
from cirrus.collectors.users import UsersCollector
from cirrus.workflows.base import BaseWorkflow


class ATOWorkflow(BaseWorkflow):
    name = "ATO"
    description = "Account Takeover investigation — authentication layer and persistence"

    def _build_steps(
        self,
        users: list[str] | None,
        start_dt: datetime,
        end_dt: datetime,
        **kwargs,
    ) -> list[tuple]:
        return [
            (
                UsersCollector,
                {"users": users, "start_dt": start_dt},
                "Resolving target user(s)",
            ),
            (
                SignInLogsCollector,
                {"users": users, "start_dt": start_dt, "end_dt": end_dt},
                "Sign-in logs",
            ),
            (
                AuditLogsCollector,
                {"users": users, "start_dt": start_dt, "end_dt": end_dt},
                "Entra directory audit logs",
            ),
            (
                MFAMethodsCollector,
                {"users": users, "start_dt": start_dt},
                "MFA / authentication methods",
            ),
            (
                RiskyUsersCollector,
                {"users": users},
                "Risky users (Identity Protection)",
            ),
            (
                RiskySignInsCollector,
                {"users": users, "start_dt": start_dt, "end_dt": end_dt},
                "Risky sign-ins (Identity Protection)",
            ),
            (
                ConditionalAccessCollector,
                {},
                "Conditional Access policies",
            ),
            (
                RegisteredDevicesCollector,
                {"users": users, "start_dt": start_dt},
                "Registered devices",
            ),
            (
                OAuthGrantsCollector,
                {"users": users},
                "OAuth app grants",
            ),
            (
                AppRegistrationsCollector,
                {"start_dt": start_dt, "end_dt": end_dt},
                "App registrations",
            ),
            (
                SPSignInLogsCollector,
                {"start_dt": start_dt, "end_dt": end_dt},
                "Service principal sign-in logs",
            ),
            (
                PIMActivationsCollector,
                {"users": users, "start_dt": start_dt, "end_dt": end_dt},
                "PIM role activation history",
            ),
            (
                UnifiedAuditCollector,
                {"users": users, "start_dt": start_dt, "end_dt": end_dt,
                 "poll_timeout": kwargs.get("ual_timeout", POLL_TIMEOUT)},
                "Unified Audit Log (UAL)",
            ),
        ]
