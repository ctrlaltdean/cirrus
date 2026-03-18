"""
Workflow: BEC + ATO Combined Investigation

Combines the Business Email Compromise and Account Takeover workflows into a
single run. Use this when you need to investigate both how an account was
compromised (authentication layer, persistence) and what the attacker did
with access (mailbox rules, forwarding, mail exfiltration).

This is the most common real-world scenario: most BEC incidents begin with
an ATO event. Running both workflows together produces a single case folder
covering the full attack chain without duplicating shared collectors.

Attack chain covered:
  ATO phase  — initial access, persistence (devices, MFA, OAuth, app registrations)
  BEC phase  — mailbox manipulation (rules, forwarding, wire fraud enablement)
  Overlap    — sign-in logs, audit events, and UAL cover both phases

Collection order (shared collectors run once):
  1.  Users                — account roster, creation dates, MFA status
  2.  Sign-in logs         — authentication timeline; impossible travel, legacy
                             auth, device code phishing, risk signals
  3.  Entra audit logs     — MFA changes, password resets, role assignments,
                             CA policy changes, app consent events
  4.  MFA methods          — current registered methods per account
  5.  Risky users          — Identity Protection risk scoring (P2)
  6.  Risky sign-ins       — Identity Protection risk events (P2)
  7.  Conditional Access   — what enforcement was in place at time of access
  8.  Registered devices   — PRT-bearing devices added during the window
  9.  OAuth grants         — persistent app consent (survives password reset)
 10.  App registrations    — new apps created in tenant during the window
 11.  Mailbox rules        — hide / forward / delete rules (BEC persistence)
 12.  Mail forwarding      — SMTP forwarding to external address
 13.  UAL                  — MailItemsAccessed, file downloads, mail sent,
                             sharing events, forwarding rules set via OWA

Typical usage:
    cirrus run bec-ato --tenant contoso.com --user john@contoso.com --days 30
    cirrus run bec-ato --tenant contoso.com --user john@contoso.com --start-date 2026-03-01 --end-date 2026-03-18
"""

from __future__ import annotations

from datetime import datetime

from cirrus.collectors.app_registrations import AppRegistrationsCollector
from cirrus.collectors.audit_logs import AuditLogsCollector
from cirrus.collectors.conditional_access import ConditionalAccessCollector
from cirrus.collectors.mail_forwarding import MailForwardingCollector
from cirrus.collectors.mailbox_rules import MailboxRulesCollector
from cirrus.collectors.mfa_methods import MFAMethodsCollector
from cirrus.collectors.oauth_grants import OAuthGrantsCollector
from cirrus.collectors.registered_devices import RegisteredDevicesCollector
from cirrus.collectors.risky_users import RiskySignInsCollector, RiskyUsersCollector
from cirrus.collectors.signin_logs import SignInLogsCollector
from cirrus.collectors.unified_audit import UnifiedAuditCollector
from cirrus.collectors.users import UsersCollector
from cirrus.workflows.base import BaseWorkflow


class BECATOWorkflow(BaseWorkflow):
    name = "BEC+ATO"
    description = "Combined BEC + ATO investigation — full attack chain collection"

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
                MFAMethodsCollector,
                {"users": users},
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
                UnifiedAuditCollector,
                {"users": users, "start_dt": start_dt, "end_dt": end_dt},
                "Unified Audit Log (UAL)",
            ),
        ]
