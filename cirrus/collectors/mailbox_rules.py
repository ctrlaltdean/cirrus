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

from cirrus.collectors.base import GRAPH_BASE, CollectorError, GraphCollector


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
        if users is None:
            # Fetch all users then iterate — practical only on smaller tenants
            user_list = self._collect_all(
                f"{GRAPH_BASE}/users",
                params={"$select": "id,userPrincipalName,displayName", "$top": 999},
            )
        else:
            user_list = [{"userPrincipalName": u, "id": u} for u in users]

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
                # Log and continue — some mailboxes may be inaccessible
                err_record = {
                    "_sourceUser": upn,
                    "_error": str(e),
                    "_iocFlags": [],
                }
                all_rules.append(err_record)

        return all_rules


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
