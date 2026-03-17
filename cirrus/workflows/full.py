"""
Workflow: Full Tenant Collection

Sweeps the entire tenant for all supported artifact types.
Use this for broad incident response, proactive threat hunting,
or when the compromised account(s) are not yet identified.

WARNING: On large tenants this can take a significant amount of time
and generate large output files. Consider using the BEC workflow
with targeted users first if a compromised account is known.

Typical usage:
    cirrus run full --tenant contoso.com --all-users --days 90
    cirrus run full --tenant contoso.com --days 30
"""

from __future__ import annotations

from cirrus.collectors.audit_logs import AuditLogsCollector
from cirrus.collectors.conditional_access import ConditionalAccessCollector
from cirrus.collectors.mail_forwarding import MailForwardingCollector
from cirrus.collectors.mailbox_rules import MailboxRulesCollector
from cirrus.collectors.mfa_methods import MFAMethodsCollector
from cirrus.collectors.oauth_grants import OAuthGrantsCollector
from cirrus.collectors.risky_users import RiskySignInsCollector, RiskyUsersCollector
from cirrus.collectors.service_principals import ServicePrincipalsCollector
from cirrus.collectors.signin_logs import SignInLogsCollector
from cirrus.collectors.unified_audit import UnifiedAuditCollector
from cirrus.collectors.users import UsersCollector
from cirrus.workflows.base import BaseWorkflow


class FullWorkflow(BaseWorkflow):
    name = "full"
    description = "Full tenant sweep — collects all supported artifact types"

    def _build_steps(
        self,
        users: list[str] | None,
        days: int,
        **kwargs,
    ) -> list[tuple]:
        return [
            (
                UsersCollector,
                {"users": users},
                "User directory",
            ),
            (
                SignInLogsCollector,
                {"days": days, "users": users},
                "Sign-in logs",
            ),
            (
                AuditLogsCollector,
                {"days": days, "users": users},
                "Entra directory audit logs",
            ),
            (
                RiskyUsersCollector,
                {"users": users},
                "Risky users",
            ),
            (
                RiskySignInsCollector,
                {"days": days, "users": users},
                "Risky sign-ins",
            ),
            (
                MFAMethodsCollector,
                {"users": users},
                "MFA / authentication methods",
            ),
            (
                MailboxRulesCollector,
                {"users": users},
                "Mailbox inbox rules",
            ),
            (
                MailForwardingCollector,
                {"users": users},
                "Mailbox forwarding settings",
            ),
            (
                OAuthGrantsCollector,
                {"users": users},
                "OAuth app grants",
            ),
            (
                ConditionalAccessCollector,
                {},
                "Conditional Access policies",
            ),
            (
                ServicePrincipalsCollector,
                {"days": None},
                "Service principals",
            ),
            (
                UnifiedAuditCollector,
                {"days": days, "users": users},
                "Unified Audit Log (UAL)",
            ),
        ]
