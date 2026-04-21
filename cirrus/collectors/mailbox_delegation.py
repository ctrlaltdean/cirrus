"""
Collector: Mailbox Delegation (Calendar Permissions & Shared Mailbox Markers)

Endpoints:
  GET /users/{id}/calendar/calendarPermissions  — per-user calendar delegates
  GET /users/{id}/mailboxSettings               — shared mailbox indicators

Requires:  Calendars.Read, MailboxSettings.Read

Mailbox delegation is a common BEC persistence mechanism that survives password
resets. Attackers who gain access to a mailbox may:
  - Grant a controlled account calendar access (to monitor meetings, intercept
    wire-transfer requests, or schedule fraud-enabling events)
  - Convert the mailbox to a shared mailbox (accessible without credentials)
  - Add Send-As or Full-Access permissions via Exchange (not visible via Graph;
    those appear in the Unified Audit Log as Add-MailboxPermission events)

This collector covers what the Graph API exposes natively. For full mailbox
permission audit (Add-MailboxPermission events), filter the Unified Audit Log.

Key IOCs:
  - External delegate with CanEdit or CanViewAll permission
  - Any delegate added with Write permission (can create/modify events)
  - Shared mailbox with forwarding or access grants
  - High-privilege delegate (CanEdit, CanViewAll) for any non-owner account
"""

from __future__ import annotations

from cirrus.collectors.base import GRAPH_BASE, CollectorError, GraphCollector


class MailboxDelegationCollector(GraphCollector):
    name = "mailbox_delegation"

    def collect(
        self,
        users: list[str] | None = None,
    ) -> list[dict]:
        """
        Collect calendar delegation records per user.

        Returns one record per delegate relationship found, annotated with
        IOC flags. Clean mailboxes (no delegates) are not included.
        """
        user_list = self._resolve_users(users, select="id,userPrincipalName,displayName,mail")

        results: list[dict] = []
        for user in user_list:
            upn = user.get("userPrincipalName") or user.get("id", "unknown")
            upn_domain = upn.split("@")[-1].lower() if "@" in upn else ""

            try:
                permissions = self._collect_all(
                    f"{GRAPH_BASE}/users/{upn}/calendar/calendarPermissions",
                    params={},
                )
            except CollectorError as e:
                if "404" in str(e):
                    continue  # no mailbox — skip silently
                results.append({"_sourceUser": upn, "_error": str(e), "_iocFlags": []})
                continue

            for perm in permissions:
                # Skip the owner's own entry
                if perm.get("isInsideOrganization") is None:
                    continue
                email_address = (perm.get("emailAddress") or {})
                delegate_addr = (email_address.get("address") or "").lower()
                delegate_name = email_address.get("name") or ""
                role = (perm.get("role") or "none").lower()

                # Skip "none" role (no actual access granted)
                if role == "none":
                    continue

                delegate_domain = delegate_addr.split("@")[-1] if "@" in delegate_addr else ""
                is_external = bool(delegate_domain and delegate_domain != upn_domain)
                inside_org = perm.get("isInsideOrganization", True)

                record = {
                    "_sourceUser": upn,
                    "delegateEmail": delegate_addr,
                    "delegateName": delegate_name,
                    "role": role,
                    "isExternal": is_external or not inside_org,
                    "canViewPrivateItems": perm.get("allowedRoles") and "read" in str(perm.get("allowedRoles", [])).lower(),
                    "_iocFlags": _flag_delegation(upn, delegate_addr, role, is_external or not inside_org),
                }
                results.append(record)

        return results


def _flag_delegation(upn: str, delegate_addr: str, role: str, is_external: bool) -> list[str]:
    flags: list[str] = []

    write_roles = {"canedit", "canviewall", "write", "freebusyreadevent",
                   "limitedread", "read"}
    high_roles  = {"canedit", "canviewall", "write"}

    role_lower = role.lower()

    if is_external:
        flags.append(f"EXTERNAL_CALENDAR_DELEGATE:{delegate_addr}")
        if role_lower in high_roles:
            flags.append(f"EXTERNAL_DELEGATE_HIGH_PERMISSION:{role}")
    elif role_lower in high_roles:
        flags.append(f"INTERNAL_DELEGATE_HIGH_PERMISSION:{role}")

    return flags
