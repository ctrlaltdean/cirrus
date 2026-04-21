"""
Shared IOC Flag Registry

Central catalogue of every flag name / prefix used by CIRRUS collectors and
the correlation engine.  Collectors and analysis modules should import flag
names from here rather than hard-coding strings, so that:

  1. Typos are caught at import time (NameError) instead of silently mis-matching.
  2. The correlator and reports reference the exact same strings as the collectors.
  3. New flags are easy to discover by reading one file.

Naming conventions:
  PREFIX          — binary flag, no parameter  (e.g. PERMANENT_DELETE)
  PREFIX:value    — parametric flag            (e.g. FORWARDS_TO:evil@attacker.com)

For parametric flags this module exports the *prefix* (without the colon);
the collector appends ":" + the specific value at runtime.

Groups below mirror the collector that first introduces the flag.
"""

from __future__ import annotations


# ── Sign-in logs (signin_logs.py) ────────────────────────────────────────────
FAILED_SIGNIN           = "FAILED_SIGNIN"
LEGACY_AUTH             = "LEGACY_AUTH"
SUSPICIOUS_AUTH_PROTOCOL = "SUSPICIOUS_AUTH_PROTOCOL"
SINGLE_FACTOR_SUCCESS   = "SINGLE_FACTOR_SUCCESS"
CA_POLICY_FAILURE       = "CA_POLICY_FAILURE"
RISK_LEVEL              = "RISK_LEVEL"
RISK_STATE              = "RISK_STATE"
GEO_RISK                = "GEO_RISK"
IDENTITY_RISK           = "IDENTITY_RISK"
RISK_DETAIL             = "RISK_DETAIL"
FLAGGED_FOR_REVIEW      = "FLAGGED_FOR_REVIEW"
PUBLIC_IP               = "PUBLIC_IP"
COUNTRY                 = "COUNTRY"
CITY                    = "CITY"
IMPOSSIBLE_TRAVEL       = "IMPOSSIBLE_TRAVEL"

# ── Mailbox rules (mailbox_rules.py) ─────────────────────────────────────────
FORWARDS_TO             = "FORWARDS_TO"
MOVES_TO_HIDDEN_FOLDER  = "MOVES_TO_HIDDEN_FOLDER"
PERMANENT_DELETE         = "PERMANENT_DELETE"
MARKS_AS_READ           = "MARKS_AS_READ"
SUSPICIOUS_KEYWORD      = "SUSPICIOUS_KEYWORD"

# ── Mail forwarding (mail_forwarding.py) ─────────────────────────────────────
EXTERNAL_SMTP_FORWARD   = "EXTERNAL_SMTP_FORWARD"
INTERNAL_SMTP_FORWARD   = "INTERNAL_SMTP_FORWARD"
FORWARDING_ADDRESS      = "FORWARDING_ADDRESS"
NO_LOCAL_COPY           = "NO_LOCAL_COPY"

# ── MFA methods (mfa_methods.py) ─────────────────────────────────────────────
HIGH_PERSISTENCE_METHOD = "HIGH_PERSISTENCE_METHOD"
RECENTLY_ADDED          = "RECENTLY_ADDED"
EXTERNAL_EMAIL_OTP      = "EXTERNAL_EMAIL_OTP"
USABLE_TEMP_ACCESS_PASS = "USABLE_TEMP_ACCESS_PASS"

# ── OAuth grants (oauth_grants.py) ───────────────────────────────────────────
HIGH_RISK_SCOPE                         = "HIGH_RISK_SCOPE"
COMBO_MAIL_READ_AND_FORWARDING_CONTROL  = "COMBO_MAIL_READ_AND_FORWARDING_CONTROL"
COMBO_FILES_AND_DIRECTORY_ACCESS        = "COMBO_FILES_AND_DIRECTORY_ACCESS"
COMBO_ROLE_MANAGEMENT_AND_DATA_ACCESS   = "COMBO_ROLE_MANAGEMENT_AND_DATA_ACCESS"
COMBO_PERSISTENT_MAIL_ACCESS            = "COMBO_PERSISTENT_MAIL_ACCESS"

# ── App registrations (app_registrations.py) ─────────────────────────────────
RECENTLY_CREATED        = "RECENTLY_CREATED"
NO_VERIFIED_PUBLISHER   = "NO_VERIFIED_PUBLISHER"
MULTI_TENANT            = "MULTI_TENANT"
HAS_APP_PERMISSIONS     = "HAS_APP_PERMISSIONS"
HAS_CLIENT_SECRETS      = "HAS_CLIENT_SECRETS"
HAS_CERTIFICATES        = "HAS_CERTIFICATES"
LOCALHOST_REDIRECT      = "LOCALHOST_REDIRECT"
PLAINTEXT_REDIRECT      = "PLAINTEXT_REDIRECT"

# ── Audit logs (audit_logs.py) ───────────────────────────────────────────────
OPERATION_FAILED        = "OPERATION_FAILED"
USER_CREATED            = "USER_CREATED"
USER_DELETED            = "USER_DELETED"
USER_DISABLED           = "USER_DISABLED"
USER_ENABLED            = "USER_ENABLED"
ADMIN_PASSWORD_RESET    = "ADMIN_PASSWORD_RESET"
USER_PASSWORD_CHANGE    = "USER_PASSWORD_CHANGE"
MFA_METHOD_ADDED        = "MFA_METHOD_ADDED"
MFA_METHOD_REMOVED      = "MFA_METHOD_REMOVED"
MFA_REGISTRATION_COMPLETE = "MFA_REGISTRATION_COMPLETE"
MFA_SETTINGS_CHANGED    = "MFA_SETTINGS_CHANGED"
ROLE_ASSIGNMENT         = "ROLE_ASSIGNMENT"
HIGH_PRIV_ROLE_ASSIGNED = "HIGH_PRIV_ROLE_ASSIGNED"
ROLE_REMOVAL            = "ROLE_REMOVAL"
APP_CONSENT_GRANTED     = "APP_CONSENT_GRANTED"
OAUTH_PERMISSION_CHANGED = "OAUTH_PERMISSION_CHANGED"
CA_POLICY_ADDED         = "CA_POLICY_ADDED"
CA_POLICY_UPDATED       = "CA_POLICY_UPDATED"
CA_POLICY_DELETED       = "CA_POLICY_DELETED"
CA_POLICY_CHANGED       = "CA_POLICY_CHANGED"
APP_REGISTRATION_CREATED = "APP_REGISTRATION_CREATED"
APP_REGISTRATION_UPDATED = "APP_REGISTRATION_UPDATED"
SERVICE_PRINCIPAL_ADDED = "SERVICE_PRINCIPAL_ADDED"
APP_OWNER_ADDED         = "APP_OWNER_ADDED"

# ── Conditional access (conditional_access.py) ───────────────────────────────
POLICY_DISABLED         = "POLICY_DISABLED"
POLICY_REPORT_ONLY      = "POLICY_REPORT_ONLY"
NO_MFA_REQUIREMENT      = "NO_MFA_REQUIREMENT"
EXCLUDES_USERS          = "EXCLUDES_USERS"
EXCLUDES_GROUPS         = "EXCLUDES_GROUPS"

# ── Registered devices (registered_devices.py) ───────────────────────────────
RECENTLY_REGISTERED     = "RECENTLY_REGISTERED"
PERSONAL_DEVICE         = "PERSONAL_DEVICE"
UNMANAGED_DEVICE        = "UNMANAGED_DEVICE"
NON_COMPLIANT           = "NON_COMPLIANT"

# ── Users (users.py) ─────────────────────────────────────────────────────────
GUEST_ACCOUNT           = "GUEST_ACCOUNT"
ACCOUNT_DISABLED        = "ACCOUNT_DISABLED"
NO_ASSIGNED_LICENSES    = "NO_ASSIGNED_LICENSES"
EXTERNAL_IDENTITY       = "EXTERNAL_IDENTITY"

# ── Service principals (service_principals.py) ───────────────────────────────
MANY_CREDENTIALS        = "MANY_CREDENTIALS"
LOCALHOST_REPLY_URL     = "LOCALHOST_REPLY_URL"
DISABLED_WITH_CREDENTIALS = "DISABLED_WITH_CREDENTIALS"
NO_OWNER_WITH_CREDENTIALS = "NO_OWNER_WITH_CREDENTIALS"

# ── SP sign-in logs (sp_signin_logs.py) ──────────────────────────────────────
FAILED_SP_AUTH          = "FAILED_SP_AUTH"
CLIENT_SECRET_CREDENTIAL = "CLIENT_SECRET_CREDENTIAL"
CERTIFICATE_CREDENTIAL  = "CERTIFICATE_CREDENTIAL"
SENSITIVE_RESOURCE      = "SENSITIVE_RESOURCE"
MANAGED_IDENTITY        = "MANAGED_IDENTITY"

# ── Mailbox delegation (mailbox_delegation.py) ───────────────────────────────
EXTERNAL_CALENDAR_DELEGATE       = "EXTERNAL_CALENDAR_DELEGATE"
EXTERNAL_DELEGATE_HIGH_PERMISSION = "EXTERNAL_DELEGATE_HIGH_PERMISSION"
INTERNAL_DELEGATE_HIGH_PERMISSION = "INTERNAL_DELEGATE_HIGH_PERMISSION"

# ── PIM activations (pim_activations.py) ─────────────────────────────────────
PIM_POLICY_CHANGE       = "PIM_POLICY_CHANGE"
PIM_EVENT               = "PIM_EVENT"
PIM_ACTIVATION          = "PIM_ACTIVATION"
HIGH_PRIV_PIM_ACTIVATION = "HIGH_PRIV_PIM_ACTIVATION"
JUSTIFICATION_MISSING   = "JUSTIFICATION_MISSING"
ACTIVATION_OUTSIDE_HOURS = "ACTIVATION_OUTSIDE_HOURS"
SELF_ACTIVATION         = "SELF_ACTIVATION"
APPROVAL_BYPASSED       = "APPROVAL_BYPASSED"

# ── Triage-specific (triage.py) ──────────────────────────────────────────────
MULTIPLE_AUTHENTICATOR_APPS = "MULTIPLE_AUTHENTICATOR_APPS"
MULTIPLE_PHONE_NUMBERS  = "MULTIPLE_PHONE_NUMBERS"
SUSPICIOUS_RULE_NAME    = "SUSPICIOUS_RULE_NAME"

# ── Correlation-generated (correlator.py) ────────────────────────────────────
HOSTING_PROVIDER_SIGNIN = "HOSTING_PROVIDER_SIGNIN"


# ── Convenience sets used by the correlator ──────────────────────────────────

SUSPICIOUS_SIGNIN_PREFIXES: tuple[str, ...] = (
    f"{SUSPICIOUS_AUTH_PROTOCOL}:",
    f"{IMPOSSIBLE_TRAVEL}:",
    f"{GEO_RISK}:",
    f"{RISK_STATE}:atRisk",
    f"{RISK_STATE}:confirmedCompromised",
    f"{IDENTITY_RISK}:",
)

PERSISTENCE_AUDIT_PREFIXES: tuple[str, ...] = (
    RECENTLY_ADDED,
    HIGH_PRIV_ROLE_ASSIGNED,
)
