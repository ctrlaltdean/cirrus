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
from cirrus.collectors.mailbox_delegation import MailboxDelegationCollector
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
                "User directory",
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
                "Risky users",
                G1,
            ),
            (
                RiskySignInsCollector,
                {"users": users, "start_dt": start_dt, "end_dt": end_dt},
                "Risky sign-ins",
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
                ConditionalAccessCollector,
                {},
                "Conditional Access policies",
                G1,
            ),
            (
                ServicePrincipalsCollector,
                {"days": None},
                "Service principals",
                G1,
            ),
            (
                SPSignInLogsCollector,
                {"start_dt": start_dt, "end_dt": end_dt},
                "Service principal sign-in logs",
                G1,
            ),
            (
                PIMActivationsCollector,
                {"start_dt": start_dt, "end_dt": end_dt},
                "PIM role activation history",
                G1,
            ),
            (
                UnifiedAuditCollector,
                {"users": users, "start_dt": start_dt, "end_dt": end_dt,
                 "poll_timeout": kwargs.get("ual_timeout", POLL_TIMEOUT)},
                "Unified Audit Log (UAL)",
                G2,
            ),
        ]
