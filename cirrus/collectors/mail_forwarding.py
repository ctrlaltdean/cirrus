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


def _normalize_ps_forwarding(ps_mb: dict) -> dict:
    """Convert Get-Mailbox PS forwarding output to Graph mailboxSettings format."""
    fwd_smtp = ps_mb.get("ForwardingSmtpAddress") or ""
    if fwd_smtp.lower().startswith("smtp:"):
        fwd_smtp = fwd_smtp[5:]
    return {
        "forwardingSmtpAddress": fwd_smtp,
        "forwardingAddress": ps_mb.get("ForwardingAddress") or "",
        "deliverToMailboxAndForward": ps_mb.get("DeliverToMailboxAndForward", True),
    }


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
        user_list = self._resolve_users(users, select="id,userPrincipalName,displayName,mail")

        # Lazy EXO token for PS fallback on 403 errors.
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
                err_str = str(e)
                if "404" in err_str:
                    continue
                # On 403, attempt Exchange Online PowerShell fallback
                if "403" in err_str:
                    ps_record = _try_ps_fallback(upn, _get_exo_token())
                    if ps_record is not None:
                        results.append(ps_record)
                        continue
                results.append({"_sourceUser": upn, "_error": err_str, "_iocFlags": []})

        return results


def _try_ps_fallback(upn: str, exo_token: str | None) -> dict | None:
    """
    Attempt to collect forwarding settings for *upn* via Exchange Online PS.
    Returns a normalized forwarding record on success, None on failure.
    """
    try:
        from cirrus.utils.exchange_ps import run_triage_mailbox_ps
        ps_data = run_triage_mailbox_ps(upn, exo_token=exo_token)
    except Exception:
        return None

    if not ps_data.get("available"):
        return None

    settings = _normalize_ps_forwarding(ps_data.get("forwarding") or {})
    fwd_smtp = settings.get("forwardingSmtpAddress")
    fwd_addr = settings.get("forwardingAddress")

    if not fwd_smtp and not fwd_addr:
        return None

    return {
        "_sourceUser": upn,
        "forwardingSmtpAddress": fwd_smtp,
        "forwardingAddress": fwd_addr,
        "deliverToMailboxAndForward": settings.get("deliverToMailboxAndForward"),
        "_iocFlags": _flag_forwarding(upn, settings),
        "_source": "exchange_ps_fallback",
    }


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
