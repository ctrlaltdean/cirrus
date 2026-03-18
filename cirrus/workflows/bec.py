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
from cirrus.collectors.mailbox_rules import MailboxRulesCollector
from cirrus.collectors.mfa_methods import MFAMethodsCollector
from cirrus.collectors.oauth_grants import OAuthGrantsCollector
from cirrus.collectors.risky_users import RiskySignInsCollector, RiskyUsersCollector
from cirrus.collectors.signin_logs import SignInLogsCollector
from cirrus.collectors.unified_audit import UnifiedAuditCollector
from cirrus.collectors.users import UsersCollector
from cirrus.workflows.base import BaseWorkflow


class BECWorkflow(BaseWorkflow):
    name = "BEC"
    description = "Business Email Compromise investigation — targeted user collection"

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
                {"users": users},
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
                UnifiedAuditCollector,
                {
                    "start_dt": start_dt,
                    "end_dt": end_dt,
                    "users": users,
                    "operations": [
                        "MailItemsAccessed",
                        "SendAs",
                        "Send",
                        "Set-Mailbox",
                        "New-InboxRule",
                        "Set-InboxRule",
                        "Remove-InboxRule",
                        "AddFolderPermissions",
                        "FileDownloaded",
                        "FileSyncDownloadedFull",
                        "AnonymousLinkCreated",
                        "SharingInvitationCreated",
                        "UserLoggedIn",
                    ],
                },
                "Unified Audit Log (UAL)",
            ),
        ]
