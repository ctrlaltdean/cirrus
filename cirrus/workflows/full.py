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

from datetime import datetime

from cirrus.collectors.audit_logs import AuditLogsCollector
from cirrus.collectors.conditional_access import ConditionalAccessCollector
from cirrus.collectors.mail_forwarding import MailForwardingCollector
from cirrus.collectors.mailbox_rules import MailboxRulesCollector
from cirrus.collectors.mfa_methods import MFAMethodsCollector
from cirrus.collectors.oauth_grants import OAuthGrantsCollector
from cirrus.collectors.risky_users import RiskySignInsCollector, RiskyUsersCollector
from cirrus.collectors.pim_activations import PIMActivationsCollector
from cirrus.collectors.service_principals import ServicePrincipalsCollector
from cirrus.collectors.signin_logs import SignInLogsCollector
from cirrus.collectors.sp_signin_logs import SPSignInLogsCollector
from cirrus.collectors.unified_audit import POLL_TIMEOUT, UnifiedAuditCollector
from cirrus.collectors.users import UsersCollector
from cirrus.workflows.base import BaseWorkflow


class FullWorkflow(BaseWorkflow):
    name = "full"
    description = "Full tenant sweep — collects all supported artifact types"

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
                "User directory",
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
                RiskyUsersCollector,
                {"users": users},
                "Risky users",
            ),
            (
                RiskySignInsCollector,
                {"users": users, "start_dt": start_dt, "end_dt": end_dt},
                "Risky sign-ins",
            ),
            (
                MFAMethodsCollector,
                {"users": users, "start_dt": start_dt},
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
                SPSignInLogsCollector,
                {"start_dt": start_dt, "end_dt": end_dt},
                "Service principal sign-in logs",
            ),
            (
                PIMActivationsCollector,
                {"start_dt": start_dt, "end_dt": end_dt},
                "PIM role activation history",
            ),
            (
                UnifiedAuditCollector,
                {"users": users, "start_dt": start_dt, "end_dt": end_dt,
                 "poll_timeout": kwargs.get("ual_timeout", POLL_TIMEOUT)},
                "Unified Audit Log (UAL)",
            ),
        ]
