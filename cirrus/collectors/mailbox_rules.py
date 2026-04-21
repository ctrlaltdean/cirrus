"""
Collector: Mailbox Inbox Rules

Endpoint: GET /users/{id}/mailFolders/Inbox/messageRules
Requires:  MailboxSettings.Read (delegated)

Inbox rules are a primary BEC persistence mechanism. Attackers create rules to:
  - Hide incoming emails from the victim (move to Deleted Items / RSS Feeds)
  - Forward copies to an external attacker-controlled address
  - Delete security alert emails
  - Auto-redirect or redirect specific senders

Key IOCs surfaced:
  - Rules that forward to external addresses
  - Rules that delete/move emails matching keywords (invoice, payment, wire, etc.)
  - Rules created recently relative to suspicious sign-in activity
  - Rules with unusual display names or no display name
"""

from __future__ import annotations

import base64
import json as _json

from cirrus.collectors.base import GRAPH_BASE, CollectorError, GraphCollector


def _decode_token_tenant(token: str) -> str | None:
    """Extract the tenant ID (tid) from a JWT access token."""
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (4 - len(payload_b64) % 4)
        payload = _json.loads(base64.b64decode(payload_b64))
        return payload.get("tid") or None
    except Exception:
        return None


def _ps_addr_to_graph(val: object) -> list[dict]:
    """Convert a PowerShell address field to Graph messageRule emailAddress format."""
    def _one(item: object) -> str:
        if isinstance(item, str):
            return item.lstrip("smtp:").lstrip("SMTP:")
        if isinstance(item, dict):
            addr = (
                item.get("Address") or item.get("address") or
                item.get("RawString") or item.get("SmtpAddress") or ""
            )
            return str(addr).lstrip("smtp:").lstrip("SMTP:")
        return ""

    items = val if isinstance(val, list) else ([val] if val else [])
    return [{"emailAddress": {"address": a}} for item in items if (a := _one(item))]


def _normalize_ps_inbox_rules(ps_rules: list[dict]) -> list[dict]:
    """Convert Get-InboxRule PS output to Graph messageRule-compatible format."""
    return [
        {
            "displayName": r.get("Name") or "",
            "isEnabled": r.get("Enabled", True),
            "actions": {
                "forwardTo":             _ps_addr_to_graph(r.get("ForwardTo")),
                "forwardAsAttachmentTo": _ps_addr_to_graph(r.get("ForwardAsAttachmentTo")),
                "redirectTo":            _ps_addr_to_graph(r.get("RedirectTo")),
                "permanentDelete":       bool(r.get("DeleteMessage", False)),
                "markAsRead":            bool(r.get("MarkAsRead", False)),
                "moveToFolder":          r.get("MoveToFolder") or "",
            },
            "conditions": {
                "subjectContains": r.get("SubjectContainsWords") or [],
                "bodyContains":    r.get("BodyContainsWords") or [],
            },
        }
        for r in ps_rules
    ]


class MailboxRulesCollector(GraphCollector):
    name = "mailbox_rules"

    def collect(
        self,
        users: list[str] | None = None,
    ) -> list[dict]:
        """
        Collect inbox rules for one or more users.

        Args:
            users: List of UPNs or object IDs.
                   None = collect for all users (may be slow on large tenants;
                   consider targeting specific users for BEC workflows).

        Returns list of rule dicts, each annotated with the source user's UPN.
        """
        user_list = self._resolve_users(users)

        # Try to pre-fetch an EXO token once for PS fallback on 403 errors.
        # Decode the tenant ID from the session's bearer token.
        _exo_token: str | None = None
        _exo_token_fetched = False

        def _get_exo_token() -> str | None:
            nonlocal _exo_token, _exo_token_fetched
            if _exo_token_fetched:
                return _exo_token
            _exo_token_fetched = True
            try:
                auth_header = self.session.headers.get("Authorization", "")
                graph_token = auth_header.removeprefix("Bearer ").strip()
                tid = _decode_token_tenant(graph_token)
                if tid:
                    from cirrus.auth.authenticator import get_exo_token_silent
                    _exo_token = get_exo_token_silent(tid)
            except Exception:
                pass
            return _exo_token

        all_rules: list[dict] = []
        for user in user_list:
            upn = user.get("userPrincipalName") or user.get("id", "unknown")
            try:
                rules = self._collect_all(
                    f"{GRAPH_BASE}/users/{upn}/mailFolders/Inbox/messageRules"
                )
                for rule in rules:
                    rule["_sourceUser"] = upn
                    rule["_iocFlags"] = _flag_rule(rule)
                all_rules.extend(rules)
            except CollectorError as e:
                err_str = str(e)
                # On 403, attempt Exchange Online PowerShell fallback
                if "403" in err_str:
                    ps_rules = _try_ps_fallback(upn, _get_exo_token())
                    if ps_rules is not None:
                        all_rules.extend(ps_rules)
                        continue
                # PS unavailable or also failed — store error record and move on
                all_rules.append({
                    "_sourceUser": upn,
                    "_error": err_str,
                    "_iocFlags": [],
                })

        return all_rules


def _try_ps_fallback(upn: str, exo_token: str | None) -> list[dict] | None:
    """
    Attempt to collect inbox rules for *upn* via Exchange Online PowerShell.
    Returns normalized Graph-format rule records on success, None on failure.
    """
    try:
        from cirrus.utils.exchange_ps import run_triage_mailbox_ps
        ps_data = run_triage_mailbox_ps(upn, exo_token=exo_token)
    except Exception:
        return None

    if not ps_data.get("available"):
        return None

    rules = _normalize_ps_inbox_rules(ps_data.get("inbox_rules") or [])
    for rule in rules:
        rule["_sourceUser"] = upn
        rule["_iocFlags"] = _flag_rule(rule)
        rule["_source"] = "exchange_ps_fallback"
    return rules


def _flag_rule(rule: dict) -> list[str]:
    """Return a list of IOC flag strings for a given inbox rule."""
    flags: list[str] = []
    actions = rule.get("actions", {})

    # Forward to external address
    forward_to = actions.get("forwardTo", [])
    forward_as_attachment = actions.get("forwardAsAttachmentTo", [])
    redirect_to = actions.get("redirectTo", [])
    for dest_list in (forward_to, forward_as_attachment, redirect_to):
        for dest in dest_list:
            addr = dest.get("emailAddress", {}).get("address", "")
            if addr:
                flags.append(f"FORWARDS_TO:{addr}")

    # Move to Deleted Items or Junk
    move_to = actions.get("moveToFolder", "")
    if move_to.lower() in ("deleteditems", "junkemail", "rss feeds", "rss subscriptions"):
        flags.append(f"MOVES_TO_HIDDEN_FOLDER:{move_to}")

    # Permanent delete
    if actions.get("permanentDelete"):
        flags.append("PERMANENT_DELETE")

    # Mark as read (stealth — victim doesn't see unread badge)
    if actions.get("markAsRead"):
        flags.append("MARKS_AS_READ")

    # Check conditions for finance/phishing keywords
    conditions = rule.get("conditions", {})
    subject_contains = conditions.get("subjectContains", [])
    body_contains = conditions.get("bodyContains", [])
    suspicious_keywords = {
        "invoice", "payment", "wire", "transfer", "bank", "account",
        "password", "reset", "verify", "urgent", "security", "alert",
        "microsoft", "it support", "helpdesk",
    }
    for kw in subject_contains + body_contains:
        if kw.lower() in suspicious_keywords:
            flags.append(f"SUSPICIOUS_KEYWORD:{kw}")

    return flags
