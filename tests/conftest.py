"""
Shared pytest fixtures and record factories for CIRRUS tests.

All fixture data is hand-crafted from the authoritative Microsoft Graph API
documentation schemas — no live tenant is required to run these tests.

Schema sources:
  sign-in records:  https://learn.microsoft.com/en-us/graph/api/resources/signin
  UAL records:      https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema
  device records:   https://learn.microsoft.com/en-us/graph/api/resources/device
  audit records:    https://learn.microsoft.com/en-us/graph/api/resources/directoryaudit
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


# ── Sign-in record factories ───────────────────────────────────────────────────

def make_signin(
    upn: str = "user@contoso.com",
    error_code: int = 0,
    ip: str = "203.0.113.10",
    country: str = "US",
    city: str = "Seattle",
    auth_protocol: str = "",
    client_app_used: str = "Browser",
    auth_req: str = "multiFactorAuthentication",
    risk_level: str = "none",
    risk_state: str = "none",
    risk_detail: str = "none",
    flagged: bool = False,
    ca_status: str = "success",
    created: str = "2026-01-15T10:00:00Z",
    ioc_flags: list[str] | None = None,
) -> dict:
    record = {
        "id": f"signin-{upn}-{created}",
        "createdDateTime": created,
        "userPrincipalName": upn,
        "userId": "00000000-0000-0000-0000-000000000001",
        "appDisplayName": "Graph Explorer",
        "appId": "de8bc8b5-d9f9-48b1-a8ad-b748da725064",
        "ipAddress": ip,
        "clientAppUsed": client_app_used,
        "authenticationProtocol": auth_protocol,
        "authenticationRequirement": auth_req,
        "conditionalAccessStatus": ca_status,
        "isInteractive": True,
        "riskDetail": risk_detail,
        "riskLevelAggregated": risk_level,
        "riskLevelDuringSignIn": risk_level,
        "riskState": risk_state,
        "flaggedForReview": flagged,
        "status": {
            "errorCode": error_code,
            "failureReason": "Other." if error_code != 0 else None,
            "additionalDetails": None,
        },
        "location": {
            "city": city,
            "state": "Washington",
            "countryOrRegion": country,
            "geoCoordinates": {},
        },
        "deviceDetail": {
            "deviceId": "",
            "displayName": None,
            "operatingSystem": "Windows 10",
            "browser": "Edge 99",
            "isCompliant": None,
            "isManaged": None,
            "trustType": None,
        },
    }
    if ioc_flags is not None:
        record["_iocFlags"] = ioc_flags
    return record


# ── MFA method record factory ─────────────────────────────────────────────────

def make_mfa(
    upn: str = "user@contoso.com",
    method_type: str = "microsoftAuthenticator",
    ioc_flags: list[str] | None = None,
    created: str = "2026-01-15T11:00:00Z",
) -> dict:
    return {
        "id": f"mfa-{upn}-{method_type}",
        "createdDateTime": created,
        "_sourceUser": upn,
        "_methodType": method_type,
        "_iocFlags": ioc_flags if ioc_flags is not None else [],
    }


# ── Registered device record factory ─────────────────────────────────────────

def make_device(
    upn: str = "user@contoso.com",
    display_name: str = "DESKTOP-ATTACKER",
    trust_type: str = "AzureAd",
    registered: str = "2026-01-15T12:00:00Z",
    ioc_flags: list[str] | None = None,
) -> dict:
    return {
        "id": f"device-{display_name}",
        "displayName": display_name,
        "registrationDateTime": registered,
        "operatingSystem": "Windows",
        "operatingSystemVersion": "10.0.22621",
        "trustType": trust_type,
        "isCompliant": False,
        "isManaged": False,
        "_sourceUser": upn,
        "_iocFlags": ioc_flags if ioc_flags is not None else [],
    }


# ── Entra audit log record factory ────────────────────────────────────────────

def make_audit(
    operation: str = "Update user",
    target_upns: list[str] | None = None,
    initiator_upn: str = "admin@contoso.com",
    ioc_flags: list[str] | None = None,
    activity_dt: str = "2026-01-15T09:00:00Z",
    ip: str = "",
) -> dict:
    target_resources = []
    for upn in (target_upns or []):
        target_resources.append({
            "id": "00000000-0000-0000-0000-000000000002",
            "displayName": upn.split("@")[0],
            "type": "User",
            "userPrincipalName": upn,
            "modifiedProperties": [],
        })

    additional_details = []
    if ip:
        additional_details.append({"key": "ipAddress", "value": ip})

    return {
        "id": f"audit-{operation}-{activity_dt}",
        "activityDateTime": activity_dt,
        "activityDisplayName": operation,
        "category": "UserManagement",
        "correlationId": "00000000-0000-0000-0000-000000000003",
        "result": "success",
        "initiatedBy": {
            "user": {
                "id": "00000000-0000-0000-0000-000000000004",
                "displayName": initiator_upn.split("@")[0],
                "userPrincipalName": initiator_upn,
                "ipAddress": ip or "198.51.100.5",
            }
        },
        "loggedByService": "Core Directory",
        "operationType": "Update",
        "targetResources": target_resources,
        "additionalDetails": additional_details,
        "_iocFlags": ioc_flags if ioc_flags is not None else [],
    }


# ── OAuth grant record factory ─────────────────────────────────────────────────

def make_oauth(
    upn: str = "user@contoso.com",
    client_id: str = "malicious-app-id",
    scope: str = "Mail.Read Files.ReadWrite",
    ioc_flags: list[str] | None = None,
) -> dict:
    return {
        "id": f"oauth-{upn}-{client_id}",
        "clientId": client_id,
        "consentType": "Principal",
        "principalId": "00000000-0000-0000-0000-000000000005",
        "resourceId": "00000003-0000-0000-c000-000000000000",
        "scope": scope,
        "_sourceUser": upn,
        "_iocFlags": ioc_flags if ioc_flags is not None else [],
    }


# ── Mailbox rule record factory ────────────────────────────────────────────────

def make_rule(
    upn: str = "user@contoso.com",
    name: str = "Forward All",
    forward_to: str = "attacker@evil.com",
    ioc_flags: list[str] | None = None,
) -> dict:
    return {
        "Identity": f"{upn}\\{name}",
        "Name": name,
        "ForwardTo": [forward_to],
        "Enabled": True,
        "_sourceUser": upn,
        "_iocFlags": ioc_flags if ioc_flags is not None else [f"FORWARDS_TO:{forward_to}"],
    }


# ── Mail forwarding record factory ─────────────────────────────────────────────

def make_forwarding(
    upn: str = "user@contoso.com",
    smtp_fwd: str = "attacker@evil.com",
    ioc_flags: list[str] | None = None,
) -> dict:
    return {
        "UserPrincipalName": upn,
        "ForwardingSmtpAddress": f"smtp:{smtp_fwd}",
        "DeliverToMailboxAndForward": False,
        "_sourceUser": upn,
        "_iocFlags": ioc_flags if ioc_flags is not None else [
            f"EXTERNAL_SMTP_FORWARD:{smtp_fwd}",
            "NO_LOCAL_COPY:",
        ],
    }


# ── User record factory ────────────────────────────────────────────────────────

def make_user(
    upn: str = "user@contoso.com",
    created: str = "2026-01-10T08:00:00Z",
    ioc_flags: list[str] | None = None,
) -> dict:
    return {
        "id": "00000000-0000-0000-0000-000000000006",
        "userPrincipalName": upn,
        "displayName": upn.split("@")[0],
        "createdDateTime": created,
        "accountEnabled": True,
        "_iocFlags": ioc_flags if ioc_flags is not None else [],
    }


# ── UAL (Unified Audit Log) record factory ─────────────────────────────────────

def make_ual_mail_access(
    upn: str = "victim@contoso.com",
    app_id: str = "00000002-0000-0ff1-ce00-000000000000",
    created: str = "2026-01-15T10:00:00Z",
) -> dict:
    return {
        "Id": f"ual-mail-{upn}-{created}",
        "RecordType": 50,
        "CreationTime": created,
        "createdDateTime": created,
        "Operation": "MailItemsAccessed",
        "operation": "MailItemsAccessed",
        "OrganizationId": "12345678-1234-1234-1234-123456789012",
        "UserType": 0,
        "UserKey": upn,
        "Workload": "Exchange",
        "ResultStatus": "Succeeded",
        "UserId": upn,
        "userId": upn,
        "ClientIP": "203.0.113.55",
        "auditData": {
            "AppId": app_id,
            "ClientIPAddress": "203.0.113.55",
            "MailboxOwnerUPN": upn,
            "Operation": "MailItemsAccessed",
            "OperationCount": 5,
        },
        "_iocFlags": [],
    }


# ── Case directory writer helper ──────────────────────────────────────────────

def write_case_files(case_dir: Path, **collector_data: list[dict]) -> None:
    """
    Write collector JSON files into a case directory.

    Keyword arguments map collector key names to record lists:
        write_case_files(tmp_path,
            signin_logs=[...],
            unified_audit_log=[...],
        )

    Filename mapping follows _COLLECTOR_FILES in correlator.py.
    """
    filename_map = {
        "signin_logs":        "signin_logs.json",
        "audit_logs":         "entra_audit_logs.json",
        "mfa_methods":        "mfa_methods.json",
        "users":              "users.json",
        "registered_devices": "registered_devices.json",
        "oauth_grants":       "oauth_grants.json",
        "mailbox_rules":      "mailbox_rules.json",
        "mail_forwarding":    "mail_forwarding.json",
        "unified_audit_log":  "unified_audit_log.json",
    }
    case_dir.mkdir(parents=True, exist_ok=True)
    for key, records in collector_data.items():
        filename = filename_map[key]
        (case_dir / filename).write_text(
            json.dumps(records, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
