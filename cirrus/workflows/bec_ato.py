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
 11.  SP sign-in logs      — service principal authentication events
 12.  PIM activations      — Privileged Identity Management role activations (P2)
 13.  Mailbox rules        — hide / forward / delete rules (BEC persistence)
 14.  Mail forwarding      — SMTP forwarding to external address
 15.  Mailbox delegation   — calendar delegation permissions
 16.  UAL                  — MailItemsAccessed, file downloads, mail sent,
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
from cirrus.collectors.mailbox_delegation import MailboxDelegationCollector
from cirrus.collectors.mailbox_rules import MailboxRulesCollector
from cirrus.collectors.mfa_methods import MFAMethodsCollector
from cirrus.collectors.oauth_grants import OAuthGrantsCollector
from cirrus.collectors.pim_activations import PIMActivationsCollector
from cirrus.collectors.registered_devices import RegisteredDevicesCollector
from cirrus.collectors.risky_users import RiskySignInsCollector, RiskyUsersCollector
from cirrus.collectors.signin_logs import SignInLogsCollector
from cirrus.collectors.sp_signin_logs import SPSignInLogsCollector
from cirrus.collectors.unified_audit import POLL_TIMEOUT, UnifiedAuditCollector
from cirrus.collectors.users import UsersCollector
from cirrus.workflows.base import BaseWorkflow


class BECATOWorkflow(BaseWorkflow):
    name = "BEC+ATO"
    description = "Combined BEC + ATO investigation — full attack chain collection"

    # Parallel execution groups:
    #   Group 0 — UsersCollector (must resolve users before anything else)
    #   Group 1 — All independent Graph / Exchange collectors (run in parallel)
    #   Group 2 — UAL (long-running, benefits from running after lighter collectors)
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
                MFAMethodsCollector,
                {"users": users, "start_dt": start_dt},
                "MFA / authentication methods",
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
                ConditionalAccessCollector,
                {},
                "Conditional Access policies",
                G1,
            ),
            (
                RegisteredDevicesCollector,
                {"users": users, "start_dt": start_dt},
                "Registered devices",
                G1,
            ),
            (
                OAuthGrantsCollector,
                {"users": users},
                "OAuth app grants",
                G1,
            ),
            (
                AppRegistrationsCollector,
                {"start_dt": start_dt, "end_dt": end_dt},
                "App registrations",
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
                {"users": users, "start_dt": start_dt, "end_dt": end_dt},
                "PIM role activation history",
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
                UnifiedAuditCollector,
                {"users": users, "start_dt": start_dt, "end_dt": end_dt,
                 "poll_timeout": kwargs.get("ual_timeout", POLL_TIMEOUT)},
                "Unified Audit Log (UAL)",
                G2,
            ),
        ]
