"""
Workflow: Business Email Compromise (BEC) Investigation

Collects the targeted set of artifacts most relevant to a BEC investigation,
in the order that best supports triage and timeline reconstruction.

Collection order (each step informs the next):
  1. Users         — resolve target account details
  2. Sign-in logs  — establish attacker access window
  3. Entra audit   — MFA changes, password resets, role assignments
  4. Risky users   — Microsoft's own risk scoring for targets
  5. Risky sign-ins — High-risk sign-in events for targets
  6. MFA methods   — current registered MFA (look for attacker-added methods)
  7. Mailbox rules  — look for hide/forward/delete rules
  8. Mail forwarding — look for SMTP forwarding to external address
  9. OAuth grants   — look for malicious app consent
 10. UAL            — MailItemsAccessed, mail reads, file downloads

Typical usage:
    cirrus run bec --tenant contoso.com --user john@contoso.com --days 30
"""

from __future__ import annotations

from datetime import datetime

from cirrus.collectors.audit_logs import AuditLogsCollector
from cirrus.collectors.mail_forwarding import MailForwardingCollector
from cirrus.collectors.mailbox_delegation import MailboxDelegationCollector
from cirrus.collectors.mailbox_rules import MailboxRulesCollector
from cirrus.collectors.mfa_methods import MFAMethodsCollector
from cirrus.collectors.oauth_grants import OAuthGrantsCollector
from cirrus.collectors.risky_users import RiskySignInsCollector, RiskyUsersCollector
from cirrus.collectors.signin_logs import SignInLogsCollector
from cirrus.collectors.unified_audit import POLL_TIMEOUT, UnifiedAuditCollector
from cirrus.collectors.users import UsersCollector
from cirrus.workflows.base import BaseWorkflow


class BECWorkflow(BaseWorkflow):
    name = "BEC"
    description = "Business Email Compromise investigation — targeted user collection"

    _G_INIT = 0
    _G_PARALLEL = 1
    _G_UAL = 2

    def _build_steps(
        self,
        users: list[str] | None,
        start_dt: datetime,
        end_dt: datetime,
        **kwargs,
    ) -> list[tuple]:
        G0, G1, G2 = self._G_INIT, self._G_PARALLEL, self._G_UAL
        return [
            (
                UsersCollector,
                {"users": users, "start_dt": start_dt},
                "Resolving target user(s)",
                G0,
            ),
            (
                SignInLogsCollector,
                {"users": users, "start_dt": start_dt, "end_dt": end_dt},
                "Sign-in logs",
                G1,
            ),
            (
                AuditLogsCollector,
                {"users": users, "start_dt": start_dt, "end_dt": end_dt},
                "Entra directory audit logs",
                G1,
            ),
            (
                RiskyUsersCollector,
                {"users": users},
                "Risky users (Identity Protection)",
                G1,
            ),
            (
                RiskySignInsCollector,
                {"users": users, "start_dt": start_dt, "end_dt": end_dt},
                "Risky sign-ins (Identity Protection)",
                G1,
            ),
            (
                MFAMethodsCollector,
                {"users": users, "start_dt": start_dt},
                "MFA / authentication methods",
                G1,
            ),
            (
                MailboxRulesCollector,
                {"users": users},
                "Mailbox inbox rules",
                G1,
            ),
            (
                MailForwardingCollector,
                {"users": users},
                "Mailbox forwarding settings",
                G1,
            ),
            (
                MailboxDelegationCollector,
                {"users": users},
                "Mailbox calendar delegation",
                G1,
            ),
            (
                OAuthGrantsCollector,
                {"users": users},
                "OAuth app grants",
                G1,
            ),
            (
                UnifiedAuditCollector,
                {
                    "start_dt": start_dt,
                    "end_dt": end_dt,
                    "users": users,
                    "poll_timeout": kwargs.get("ual_timeout", POLL_TIMEOUT),
                },
                "Unified Audit Log (UAL)",
                G2,
            ),
        ]
