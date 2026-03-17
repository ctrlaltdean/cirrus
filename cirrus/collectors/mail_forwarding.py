"""
Collector: Mailbox Forwarding Settings

Endpoint: GET /users/{id}/mailboxSettings
Requires:  MailboxSettings.Read

Distinct from inbox rules — this is SMTP forwarding configured directly
on the mailbox object (not as a rule). Attackers set this via:
  - OWA settings
  - Exchange admin center
  - PowerShell Set-Mailbox / Graph API PATCH

forwardingSmtpAddress: external SMTP address to forward all mail to
forwardingAddress:     internal recipient to forward to
deliverToMailboxAndForward: whether to also keep a copy in the original mailbox

Key IOCs:
  - forwardingSmtpAddress set to external domain (attacker's mailbox)
  - deliverToMailboxAndForward = false (victim gets nothing, total exfiltration)
  - forwardingAddress set to a suspicious internal mailbox
"""

from __future__ import annotations

from cirrus.collectors.base import GRAPH_BASE, CollectorError, GraphCollector


class MailForwardingCollector(GraphCollector):
    name = "mail_forwarding"

    def collect(
        self,
        users: list[str] | None = None,
    ) -> list[dict]:
        """
        Collect mailbox forwarding settings.

        Returns only users that have ANY forwarding configured
        (forwardingSmtpAddress or forwardingAddress is non-null),
        plus an IOC flag if forwarding is to an external address.
        """
        if users is None:
            user_list = self._collect_all(
                f"{GRAPH_BASE}/users",
                params={"$select": "id,userPrincipalName,displayName,mail", "$top": 999},
            )
        else:
            user_list = [{"userPrincipalName": u, "id": u} for u in users]

        results: list[dict] = []
        for user in user_list:
            upn = user.get("userPrincipalName") or user.get("id", "unknown")
            try:
                settings = self._get(
                    f"{GRAPH_BASE}/users/{upn}/mailboxSettings",
                )
                fwd_smtp = settings.get("forwardingSmtpAddress")
                fwd_addr = settings.get("forwardingAddress")

                if fwd_smtp or fwd_addr:
                    record = {
                        "_sourceUser": upn,
                        "forwardingSmtpAddress": fwd_smtp,
                        "forwardingAddress": fwd_addr,
                        "deliverToMailboxAndForward": settings.get("deliverToMailboxAndForward"),
                        "automaticRepliesStatus": settings.get("automaticRepliesSetting", {}).get("status"),
                        "_iocFlags": _flag_forwarding(upn, settings),
                    }
                    results.append(record)

            except CollectorError as e:
                if "404" not in str(e):
                    results.append({"_sourceUser": upn, "_error": str(e), "_iocFlags": []})

        return results


def _flag_forwarding(upn: str, settings: dict) -> list[str]:
    flags: list[str] = []
    fwd_smtp = settings.get("forwardingSmtpAddress", "") or ""
    fwd_addr = settings.get("forwardingAddress", "") or ""
    deliver_and_forward = settings.get("deliverToMailboxAndForward", True)

    # Extract domain of the UPN
    upn_domain = upn.split("@")[-1].lower() if "@" in upn else ""

    if fwd_smtp:
        fwd_domain = fwd_smtp.split("@")[-1].lower() if "@" in fwd_smtp else ""
        if fwd_domain and fwd_domain != upn_domain:
            flags.append(f"EXTERNAL_SMTP_FORWARD:{fwd_smtp}")
        else:
            flags.append(f"INTERNAL_SMTP_FORWARD:{fwd_smtp}")

    if fwd_addr:
        flags.append(f"FORWARDING_ADDRESS:{fwd_addr}")

    if (fwd_smtp or fwd_addr) and not deliver_and_forward:
        flags.append("NO_LOCAL_COPY:victim_receives_nothing")

    return flags
