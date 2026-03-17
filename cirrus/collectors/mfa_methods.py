"""
Collector: MFA / Authentication Methods

Endpoint: GET /users/{id}/authentication/methods
Requires:  UserAuthenticationMethod.Read.All

After compromising an account, attackers often register a new MFA method
(authenticator app, phone number) to maintain persistent access even after
the victim changes their password.

Key IOCs:
  - Phone/authenticator added within 24–48h of suspicious sign-in
  - Multiple MFA methods registered (especially from different devices)
  - FIDO2 key or certificate added (more persistent, harder to notice)
  - Email OTP address pointing to external/attacker domain
"""

from __future__ import annotations

from cirrus.collectors.base import GRAPH_BASE, CollectorError, GraphCollector


class MFAMethodsCollector(GraphCollector):
    name = "mfa_methods"

    def collect(
        self,
        users: list[str] | None = None,
    ) -> list[dict]:
        """
        Collect authentication methods for each user.

        Args:
            users: List of UPNs. None = all users (slow on large tenants).

        Returns list of method dicts, each annotated with sourceUser.
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
                    method["_methodType"] = _normalize_method_type(method.get("@odata.type", ""))
                all_methods.extend(methods)
            except CollectorError as e:
                all_methods.append({
                    "_sourceUser": upn,
                    "_error": str(e),
                    "_methodType": "error",
                })

        return all_methods


def _normalize_method_type(odata_type: str) -> str:
    """Map @odata.type to a human-readable method name."""
    mapping = {
        "#microsoft.graph.phoneAuthenticationMethod": "phone",
        "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod": "authenticator_app",
        "#microsoft.graph.fido2AuthenticationMethod": "fido2_key",
        "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod": "windows_hello",
        "#microsoft.graph.emailAuthenticationMethod": "email_otp",
        "#microsoft.graph.passwordAuthenticationMethod": "password",
        "#microsoft.graph.softwareOathAuthenticationMethod": "software_oath_token",
        "#microsoft.graph.temporaryAccessPassAuthenticationMethod": "temporary_access_pass",
        "#microsoft.graph.certificateBasedAuthConfiguration": "certificate",
    }
    return mapping.get(odata_type.lower(), odata_type)
