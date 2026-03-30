"""
Unit tests for per-record IOC flag functions in each collector.

These are all pure functions — no network, no filesystem.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from cirrus.collectors.audit_logs import _extract_ip, _extract_role_name, _flag_audit_event
from cirrus.collectors.mfa_methods import _flag_mfa_method, _flag_multi_method_users
from cirrus.collectors.oauth_grants import _flag_grant
from cirrus.collectors.registered_devices import _flag_device
from cirrus.collectors.users import _flag_user

# ── Shared helpers ────────────────────────────────────────────────────────────

START_DT = datetime(2026, 1, 1, tzinfo=timezone.utc)
BEFORE_START = "2025-12-15T10:00:00Z"
AFTER_START = "2026-01-10T10:00:00Z"


# ═══════════════════════════════════════════════════════════════════════════════
# audit_logs — _flag_audit_event
# ═══════════════════════════════════════════════════════════════════════════════

class TestFlagAuditEvent:
    def _rec(self, activity: str, result: str = "success", extras: dict | None = None) -> dict:
        r = {
            "activityDisplayName": activity,
            "result": result,
            "targetResources": [],
            "additionalDetails": [],
        }
        if extras:
            r.update(extras)
        return r

    # ── User lifecycle ─────────────────────────────────────────────────────────

    def test_add_user_flagged(self):
        assert "USER_CREATED" in _flag_audit_event(self._rec("Add user"))

    def test_delete_user_flagged(self):
        assert "USER_DELETED" in _flag_audit_event(self._rec("Delete user"))

    def test_block_sign_in_flagged(self):
        assert "USER_DISABLED" in _flag_audit_event(self._rec("Block Sign In"))

    def test_unblock_sign_in_flagged(self):
        assert "USER_ENABLED" in _flag_audit_event(self._rec("Unblock Sign In"))

    # ── Credential operations ──────────────────────────────────────────────────

    def test_admin_password_reset_flagged(self):
        assert "ADMIN_PASSWORD_RESET" in _flag_audit_event(self._rec("Reset user password"))

    def test_user_password_change_flagged(self):
        assert "USER_PASSWORD_CHANGE" in _flag_audit_event(self._rec("Change user password"))

    # ── MFA / auth method changes ──────────────────────────────────────────────

    def test_registered_security_info_flagged(self):
        assert "MFA_METHOD_ADDED" in _flag_audit_event(
            self._rec("User registered security info")
        )

    def test_deleted_security_info_flagged(self):
        assert "MFA_METHOD_REMOVED" in _flag_audit_event(
            self._rec("User deleted security info")
        )

    def test_registered_all_security_info_flagged(self):
        assert "MFA_REGISTRATION_COMPLETE" in _flag_audit_event(
            self._rec("User registered all required security info")
        )

    def test_update_user_strongauth_flagged(self):
        record = self._rec("Update user")
        record["targetResources"] = [{
            "type": "User",
            "modifiedProperties": [
                {"displayName": "StrongAuthenticationMethods", "oldValue": "[]", "newValue": "[...]"}
            ],
        }]
        flags = _flag_audit_event(record)
        assert "MFA_SETTINGS_CHANGED" in flags

    def test_update_user_no_strongauth_not_flagged(self):
        record = self._rec("Update user")
        record["targetResources"] = [{
            "type": "User",
            "modifiedProperties": [
                {"displayName": "Department", "oldValue": "Sales", "newValue": "Finance"}
            ],
        }]
        flags = _flag_audit_event(record)
        assert "MFA_SETTINGS_CHANGED" not in flags

    # ── Role assignment ────────────────────────────────────────────────────────

    def test_role_assignment_flagged(self):
        record = self._rec("Add member to role")
        record["additionalDetails"] = [
            {"key": "Role.DisplayName", "value": "Helpdesk Administrator"}
        ]
        flags = _flag_audit_event(record)
        assert any(f.startswith("ROLE_ASSIGNMENT:") for f in flags)

    def test_high_priv_role_flagged(self):
        record = self._rec("Add member to role")
        record["additionalDetails"] = [
            {"key": "Role.DisplayName", "value": "Global Administrator"}
        ]
        flags = _flag_audit_event(record)
        assert any(f.startswith("HIGH_PRIV_ROLE_ASSIGNED:") for f in flags)

    def test_low_priv_role_no_high_priv_flag(self):
        record = self._rec("Add member to role")
        record["additionalDetails"] = [
            {"key": "Role.DisplayName", "value": "Reports Reader"}
        ]
        flags = _flag_audit_event(record)
        assert any(f.startswith("ROLE_ASSIGNMENT:") for f in flags)
        assert not any(f.startswith("HIGH_PRIV_ROLE_ASSIGNED:") for f in flags)

    def test_role_removal_flagged(self):
        record = self._rec("Remove member from role")
        record["additionalDetails"] = [{"key": "Role.DisplayName", "value": "User Administrator"}]
        flags = _flag_audit_event(record)
        assert any(f.startswith("ROLE_REMOVAL:") for f in flags)

    def test_eligible_role_assignment_flagged(self):
        record = self._rec("Add eligible member to role")
        record["additionalDetails"] = [{"key": "Role.DisplayName", "value": "Global Administrator"}]
        flags = _flag_audit_event(record)
        assert any(f.startswith("HIGH_PRIV_ROLE_ASSIGNED:") for f in flags)

    # ── OAuth / consent ────────────────────────────────────────────────────────

    def test_consent_to_application_flagged(self):
        assert "APP_CONSENT_GRANTED" in _flag_audit_event(self._rec("Consent to application"))

    def test_add_oauth2_permission_grant_flagged(self):
        assert "APP_CONSENT_GRANTED" in _flag_audit_event(
            self._rec("Add oAuth2PermissionGrant")
        )

    # ── Conditional Access ─────────────────────────────────────────────────────

    def test_ca_policy_add_flagged(self):
        assert "CA_POLICY_ADDED" in _flag_audit_event(self._rec("Add conditional access policy"))

    def test_ca_policy_update_flagged(self):
        assert "CA_POLICY_UPDATED" in _flag_audit_event(
            self._rec("Update conditional access policy")
        )

    def test_ca_policy_delete_flagged(self):
        assert "CA_POLICY_DELETED" in _flag_audit_event(
            self._rec("Delete conditional access policy")
        )

    # ── App registration ───────────────────────────────────────────────────────

    def test_add_application_flagged(self):
        assert "APP_REGISTRATION_CREATED" in _flag_audit_event(self._rec("Add application"))

    def test_add_service_principal_flagged(self):
        assert "SERVICE_PRINCIPAL_ADDED" in _flag_audit_event(self._rec("Add service principal"))

    def test_add_app_owner_flagged(self):
        assert "APP_OWNER_ADDED" in _flag_audit_event(self._rec("Add owner to application"))

    # ── Operation failure ──────────────────────────────────────────────────────

    def test_failed_operation_flagged(self):
        flags = _flag_audit_event(self._rec("Reset user password", result="failure"))
        assert any(f.startswith("OPERATION_FAILED:") for f in flags)

    def test_successful_operation_not_flagged(self):
        flags = _flag_audit_event(self._rec("Reset user password", result="success"))
        assert not any(f.startswith("OPERATION_FAILED:") for f in flags)

    # ── IP extraction ──────────────────────────────────────────────────────────

    def test_public_ip_in_additional_details_flagged(self):
        record = self._rec("Reset user password")
        record["additionalDetails"] = [{"key": "ipAddress", "value": "203.0.113.5"}]
        flags = _flag_audit_event(record)
        assert "PUBLIC_IP:203.0.113.5" in flags

    def test_private_ip_not_flagged(self):
        record = self._rec("Reset user password")
        record["additionalDetails"] = [{"key": "ipAddress", "value": "10.0.0.1"}]
        flags = _flag_audit_event(record)
        assert not any(f.startswith("PUBLIC_IP:") for f in flags)


class TestExtractRoleName:
    def test_from_additional_details(self):
        record = {
            "additionalDetails": [{"key": "Role.DisplayName", "value": "Global Administrator"}],
            "targetResources": [],
        }
        assert _extract_role_name(record) == "Global Administrator"

    def test_from_target_resources_role_type(self):
        record = {
            "additionalDetails": [],
            "targetResources": [
                {"type": "Role", "displayName": "Security Administrator", "id": "xxx"},
            ],
        }
        assert _extract_role_name(record) == "Security Administrator"

    def test_returns_none_when_not_found(self):
        assert _extract_role_name({"additionalDetails": [], "targetResources": []}) is None


class TestExtractIp:
    def test_returns_public_ip(self):
        record = {"additionalDetails": [{"key": "ipaddr", "value": "203.0.113.99"}]}
        assert _extract_ip(record) == "203.0.113.99"

    def test_returns_none_for_private_ip(self):
        record = {"additionalDetails": [{"key": "ip", "value": "192.168.1.1"}]}
        assert _extract_ip(record) is None

    def test_returns_none_when_no_ip_key(self):
        record = {"additionalDetails": [{"key": "userAgent", "value": "Chrome"}]}
        assert _extract_ip(record) is None


# ═══════════════════════════════════════════════════════════════════════════════
# mfa_methods — _flag_mfa_method, _flag_multi_method_users
# ═══════════════════════════════════════════════════════════════════════════════

class TestFlagMfaMethod:
    def _method(self, method_type: str, **kwargs) -> dict:
        return {"_methodType": method_type, "_sourceUser": "user@contoso.com", **kwargs}

    def test_fido2_key_high_persistence(self):
        m = self._method("fido2_key")
        assert "HIGH_PERSISTENCE_METHOD:fido2_key" in _flag_mfa_method(m, None)

    def test_certificate_high_persistence(self):
        m = self._method("certificate")
        assert "HIGH_PERSISTENCE_METHOD:certificate" in _flag_mfa_method(m, None)

    def test_authenticator_app_not_high_persistence(self):
        m = self._method("authenticator_app")
        assert not any(f.startswith("HIGH_PERSISTENCE_METHOD:") for f in _flag_mfa_method(m, None))

    def test_recently_added_when_after_start(self):
        m = self._method("authenticator_app", createdDateTime=AFTER_START)
        flags = _flag_mfa_method(m, START_DT)
        assert any(f.startswith("RECENTLY_ADDED:") for f in flags)

    def test_not_recently_added_when_before_start(self):
        m = self._method("authenticator_app", createdDateTime=BEFORE_START)
        flags = _flag_mfa_method(m, START_DT)
        assert not any(f.startswith("RECENTLY_ADDED:") for f in flags)

    def test_no_recently_added_when_start_dt_is_none(self):
        m = self._method("authenticator_app", createdDateTime=AFTER_START)
        flags = _flag_mfa_method(m, None)
        assert not any(f.startswith("RECENTLY_ADDED:") for f in flags)

    def test_external_email_otp_flagged(self):
        m = self._method(
            "email_otp",
            emailAddress="attacker@gmail.com",
            _sourceUser="victim@contoso.com",
        )
        m["_sourceUser"] = "victim@contoso.com"
        flags = _flag_mfa_method(m, None)
        assert any(f.startswith("EXTERNAL_EMAIL_OTP:") for f in flags)
        assert "gmail.com" in " ".join(flags)

    def test_same_domain_email_otp_not_flagged(self):
        m = self._method("email_otp", emailAddress="alice@contoso.com")
        flags = _flag_mfa_method(m, None)
        assert not any(f.startswith("EXTERNAL_EMAIL_OTP:") for f in flags)

    def test_usable_tap_flagged(self):
        m = self._method("temporary_access_pass", isUsable=True)
        assert "USABLE_TEMP_ACCESS_PASS" in _flag_mfa_method(m, None)

    def test_expired_tap_not_flagged(self):
        m = self._method("temporary_access_pass", isUsable=False)
        assert "USABLE_TEMP_ACCESS_PASS" not in _flag_mfa_method(m, None)


class TestFlagMultiMethodUsers:
    def _make_method(self, upn: str, method_type: str) -> dict:
        return {"_sourceUser": upn, "_methodType": method_type, "_iocFlags": []}

    def test_multiple_authenticator_apps_flagged(self):
        methods = [
            self._make_method("alice@c.com", "authenticator_app"),
            self._make_method("alice@c.com", "authenticator_app"),
        ]
        _flag_multi_method_users(methods)
        assert any(f.startswith("MULTIPLE_AUTHENTICATOR_APPS:") for m in methods for f in m["_iocFlags"])

    def test_single_authenticator_app_not_flagged(self):
        methods = [self._make_method("alice@c.com", "authenticator_app")]
        _flag_multi_method_users(methods)
        assert not any(f.startswith("MULTIPLE_AUTHENTICATOR_APPS:") for m in methods for f in m["_iocFlags"])

    def test_multiple_phone_numbers_flagged(self):
        methods = [
            self._make_method("bob@c.com", "phone"),
            self._make_method("bob@c.com", "phone"),
        ]
        _flag_multi_method_users(methods)
        assert any(f.startswith("MULTIPLE_PHONE_NUMBERS:") for m in methods for f in m["_iocFlags"])

    def test_different_users_not_cross_flagged(self):
        methods = [
            self._make_method("alice@c.com", "authenticator_app"),
            self._make_method("bob@c.com", "authenticator_app"),
        ]
        _flag_multi_method_users(methods)
        assert not any(f.startswith("MULTIPLE_AUTHENTICATOR_APPS:") for m in methods for f in m["_iocFlags"])


# ═══════════════════════════════════════════════════════════════════════════════
# registered_devices — _flag_device
# ═══════════════════════════════════════════════════════════════════════════════

class TestFlagDevice:
    def _device(self, **kwargs) -> dict:
        return {
            "displayName": "DESKTOP-TEST",
            "registrationDateTime": BEFORE_START,
            "trustType": "AzureAd",
            "isManaged": True,
            "isCompliant": True,
            **kwargs,
        }

    def test_recently_registered_flagged(self):
        d = self._device(registrationDateTime=AFTER_START)
        flags = _flag_device(d, START_DT)
        assert any(f.startswith("RECENTLY_REGISTERED:") for f in flags)

    def test_old_device_not_recently_registered(self):
        d = self._device(registrationDateTime=BEFORE_START)
        flags = _flag_device(d, START_DT)
        assert not any(f.startswith("RECENTLY_REGISTERED:") for f in flags)

    def test_personal_device_flagged(self):
        d = self._device(trustType="Workplace")
        flags = _flag_device(d, START_DT)
        assert "PERSONAL_DEVICE:Workplace" in flags

    def test_corporate_device_not_flagged(self):
        d = self._device(trustType="AzureAd")
        flags = _flag_device(d, START_DT)
        assert not any(f.startswith("PERSONAL_DEVICE:") for f in flags)

    def test_unmanaged_device_flagged(self):
        d = self._device(isManaged=False, isCompliant=None)
        flags = _flag_device(d, START_DT)
        assert "UNMANAGED_DEVICE" in flags

    def test_managed_noncompliant_flagged(self):
        d = self._device(isManaged=True, isCompliant=False)
        flags = _flag_device(d, START_DT)
        assert "NON_COMPLIANT" in flags

    def test_managed_compliant_no_compliance_flag(self):
        d = self._device(isManaged=True, isCompliant=True)
        flags = _flag_device(d, START_DT)
        assert "UNMANAGED_DEVICE" not in flags
        assert "NON_COMPLIANT" not in flags

    def test_no_registration_datetime_no_recent_flag(self):
        d = self._device(registrationDateTime=None)
        flags = _flag_device(d, START_DT)
        assert not any(f.startswith("RECENTLY_REGISTERED:") for f in flags)


# ═══════════════════════════════════════════════════════════════════════════════
# users — _flag_user
# ═══════════════════════════════════════════════════════════════════════════════

class TestFlagUser:
    def _user(self, **kwargs) -> dict:
        return {
            "userPrincipalName": "user@contoso.com",
            "userType": "Member",
            "accountEnabled": True,
            "createdDateTime": BEFORE_START,
            "assignedLicenses": [{"skuId": "aaa"}],
            "identities": [],
            **kwargs,
        }

    def test_recently_created_flagged(self):
        u = self._user(createdDateTime=AFTER_START)
        flags = _flag_user(u, START_DT)
        assert any(f.startswith("RECENTLY_CREATED:") for f in flags)

    def test_old_account_not_recently_created(self):
        u = self._user(createdDateTime=BEFORE_START)
        flags = _flag_user(u, START_DT)
        assert not any(f.startswith("RECENTLY_CREATED:") for f in flags)

    def test_no_recently_created_without_start_dt(self):
        u = self._user(createdDateTime=AFTER_START)
        flags = _flag_user(u, None)
        assert not any(f.startswith("RECENTLY_CREATED:") for f in flags)

    def test_guest_account_flagged(self):
        u = self._user(userType="Guest")
        assert "GUEST_ACCOUNT" in _flag_user(u, None)

    def test_member_not_flagged_as_guest(self):
        u = self._user(userType="Member")
        assert "GUEST_ACCOUNT" not in _flag_user(u, None)

    def test_disabled_account_flagged(self):
        u = self._user(accountEnabled=False)
        assert "ACCOUNT_DISABLED" in _flag_user(u, None)

    def test_enabled_account_not_flagged(self):
        u = self._user(accountEnabled=True)
        assert "ACCOUNT_DISABLED" not in _flag_user(u, None)

    def test_no_licenses_flagged(self):
        u = self._user(assignedLicenses=[])
        assert "NO_ASSIGNED_LICENSES" in _flag_user(u, None)

    def test_licensed_account_not_flagged(self):
        u = self._user(assignedLicenses=[{"skuId": "some-sku"}])
        assert "NO_ASSIGNED_LICENSES" not in _flag_user(u, None)

    def test_external_google_identity_flagged(self):
        u = self._user(identities=[{"signInType": "google.com", "issuer": "google.com", "issuerAssignedId": "x"}])
        flags = _flag_user(u, None)
        assert any(f.startswith("EXTERNAL_IDENTITY:") for f in flags)

    def test_federated_identity_flagged(self):
        u = self._user(identities=[{"signInType": "federated", "issuer": "okta.contoso.com"}])
        flags = _flag_user(u, None)
        assert any(f.startswith("EXTERNAL_IDENTITY:federated:") for f in flags)

    def test_standard_entra_identity_not_flagged(self):
        u = self._user(identities=[{"signInType": "userPrincipalName", "issuer": "contoso.com"}])
        flags = _flag_user(u, None)
        assert not any(f.startswith("EXTERNAL_IDENTITY:") for f in flags)


# ═══════════════════════════════════════════════════════════════════════════════
# oauth_grants — _flag_grant
# ═══════════════════════════════════════════════════════════════════════════════

class TestFlagGrant:
    @pytest.mark.parametrize("scope", [
        "Mail.Read",
        "Mail.ReadWrite",
        "Mail.Send",
        "MailboxSettings.ReadWrite",
        "full_access_as_user",
        "Files.Read.All",
        "Files.ReadWrite.All",
        "Directory.Read.All",
        "Directory.ReadWrite.All",
        "User.Read.All",
        "offline_access",
        "RoleManagement.ReadWrite.Directory",
    ])
    def test_high_risk_scope_flagged(self, scope: str):
        flags = _flag_grant(scope)
        assert f"HIGH_RISK_SCOPE:{scope}" in flags

    def test_low_risk_scope_not_flagged(self):
        flags = _flag_grant("User.Read openid profile email")
        assert not any(f.startswith("HIGH_RISK_SCOPE:") for f in flags)

    def test_multiple_scopes_in_one_string(self):
        flags = _flag_grant("openid profile Mail.Read User.Read offline_access")
        flagged = [f for f in flags if f.startswith("HIGH_RISK_SCOPE:")]
        assert "HIGH_RISK_SCOPE:Mail.Read" in flagged
        assert "HIGH_RISK_SCOPE:offline_access" in flagged
        # openid/profile/User.Read are not high-risk
        assert len(flagged) == 2

    def test_empty_scope_string_no_flags(self):
        assert _flag_grant("") == []

    def test_whitespace_only_no_flags(self):
        assert _flag_grant("   ") == []
