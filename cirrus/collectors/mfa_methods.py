"""
Collector: MFA / Authentication Methods

Endpoint: GET /users/{id}/authentication/methods
Requires:  UserAuthenticationMethod.Read.All

After compromising an account, attackers often register a new MFA method
(authenticator app, phone number) to maintain persistent access even after
the victim changes their password. This collector captures the *current state*
of registered methods — pair with Entra audit logs to see *when* each method
was added.

Key IOCs:
  - FIDO2 key or certificate registered (high-persistence — hard to notice,
    survives most incident response steps short of full account wipe)
  - Email OTP pointing to an external / attacker-controlled address
  - Active Temporary Access Pass (can be used for sign-in right now)
  - Multiple authenticator apps on the same account (attacker added one)
  - Multiple phone numbers registered
  - Method added during the collection window (requires start_dt)
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from cirrus.collectors.base import GRAPH_BASE, CollectorError, GraphCollector

# Method types that are especially persistent and harder to detect post-compromise
_HIGH_PERSISTENCE_TYPES = frozenset({"fido2_key", "certificate"})


def _normalize_method_type(odata_type: str) -> str:
    """Map @odata.type to a human-readable method name."""
    mapping = {
        "#microsoft.graph.phoneAuthenticationMethod":                    "phone",
        "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod":   "authenticator_app",
        "#microsoft.graph.fido2AuthenticationMethod":                    "fido2_key",
        "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod":  "windows_hello",
        "#microsoft.graph.emailAuthenticationMethod":                    "email_otp",
        "#microsoft.graph.passwordAuthenticationMethod":                 "password",
        "#microsoft.graph.softwareOathAuthenticationMethod":             "software_oath_token",
        "#microsoft.graph.temporaryAccessPassAuthenticationMethod":      "temporary_access_pass",
        "#microsoft.graph.certificateBasedAuthConfiguration":            "certificate",
    }
    return mapping.get(odata_type.lower(), odata_type)


def _flag_mfa_method(method: dict, start_dt: datetime | None) -> list[str]:
    """
    Return IOC flag strings for a single MFA method record.

    Args:
        method:   The method dict (already has _methodType and _sourceUser set).
        start_dt: Collection window start. Methods with a createdDateTime on or
                  after this date receive a RECENTLY_ADDED flag.
    """
    flags: list[str] = []
    method_type = method.get("_methodType") or ""
    source_user = method.get("_sourceUser") or ""

    # ── High-persistence methods ──────────────────────────────────────────────
    # FIDO2 keys and certificates are harder to spot in normal user reviews,
    # survive password resets, and require physical possession or PKI to abuse.
    if method_type in _HIGH_PERSISTENCE_TYPES:
        flags.append(f"HIGH_PERSISTENCE_METHOD:{method_type}")

    # ── Recently added ────────────────────────────────────────────────────────
    # Only authenticator apps and FIDO2 keys expose createdDateTime.
    created_str = method.get("createdDateTime") or ""
    if created_str and start_dt is not None:
        try:
            created_dt = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
            if created_dt >= start_dt:
                flags.append(f"RECENTLY_ADDED:{created_str[:10]}")
        except ValueError:
            pass

    # ── External email OTP ────────────────────────────────────────────────────
    # An email OTP address on a different domain from the user's UPN is a
    # strong indicator that an attacker registered a recovery email they control.
    if method_type == "email_otp":
        email = method.get("emailAddress") or ""
        if email and "@" in email:
            email_domain = email.split("@")[-1].lower()
            user_domain = source_user.split("@")[-1].lower() if "@" in source_user else ""
            if user_domain and email_domain != user_domain:
                flags.append(f"EXTERNAL_EMAIL_OTP:{email_domain}")

    # ── Active Temporary Access Pass ──────────────────────────────────────────
    # A TAP that is still usable means an attacker could use it right now
    # to authenticate without a password or MFA.
    if method_type == "temporary_access_pass" and method.get("isUsable"):
        flags.append("USABLE_TEMP_ACCESS_PASS")

    return flags


def _flag_multi_method_users(methods: list[dict]) -> None:
    """
    Post-collection pass: flag users with multiple authenticator apps or
    multiple phone numbers. Appends flags directly to each affected record.

    Legitimate users rarely need more than one authenticator app — a second
    one is a common attacker persistence pattern.
    """
    by_user_apps: dict[str, list[dict]] = defaultdict(list)
    by_user_phones: dict[str, list[dict]] = defaultdict(list)

    for method in methods:
        upn = method.get("_sourceUser") or ""
        method_type = method.get("_methodType") or ""
        if method_type == "authenticator_app":
            by_user_apps[upn].append(method)
        elif method_type == "phone":
            by_user_phones[upn].append(method)

    for upn, apps in by_user_apps.items():
        if len(apps) > 1:
            flag = f"MULTIPLE_AUTHENTICATOR_APPS:{len(apps)}"
            for m in apps:
                m["_iocFlags"].append(flag)

    for upn, phones in by_user_phones.items():
        if len(phones) > 1:
            flag = f"MULTIPLE_PHONE_NUMBERS:{len(phones)}"
            for m in phones:
                m["_iocFlags"].append(flag)


class MFAMethodsCollector(GraphCollector):
    name = "mfa_methods"

    def collect(
        self,
        users: list[str] | None = None,
        start_dt: datetime | None = None,
    ) -> list[dict]:
        """
        Collect authentication methods for each user, annotating each record
        with IOC flags.

        Args:
            users:    List of UPNs. None = all users (slow on large tenants).
            start_dt: Collection window start. Methods created on or after
                      this date receive a RECENTLY_ADDED flag.

        Returns list of method dicts, each with _iocFlags, _sourceUser,
        and _methodType.
        """
        if users is None:
            user_list = self._collect_all(
                f"{GRAPH_BASE}/users",
                params={"$select": "id,userPrincipalName,displayName", "$top": 999},
            )
        else:
            user_list = [{"userPrincipalName": u, "id": u} for u in users]

        all_methods: list[dict] = []
        for user in user_list:
            upn = user.get("userPrincipalName") or user.get("id", "unknown")
            try:
                methods = self._collect_all(
                    f"{GRAPH_BASE}/users/{upn}/authentication/methods"
                )
                for method in methods:
                    method["_sourceUser"] = upn
                    method["_methodType"] = _normalize_method_type(
                        method.get("@odata.type", "")
                    )
                    method["_iocFlags"] = _flag_mfa_method(method, start_dt)
                all_methods.extend(methods)
            except CollectorError as e:
                all_methods.append({
                    "_sourceUser": upn,
                    "_error": str(e),
                    "_methodType": "error",
                    "_iocFlags": [],
                })

        # Cross-record pass: flag users with multiple apps / phone numbers
        _flag_multi_method_users(all_methods)

        return all_methods
