"""
Collector: Registered Devices

Endpoints: GET /users/{id}/registeredDevices  (per targeted user)
           GET /devices                        (tenant-wide fallback)
Requires:  Directory.Read.All

Collects devices registered to user accounts. During an ATO, attackers
commonly register a device to gain persistent access via:
  - Primary Refresh Token (PRT) — device-bound token survives password resets
  - Device compliance bypass — a registered (not enrolled) device can satisfy
    "require compliant device" CA policies on some configurations
  - Persistent MFA satisfaction — registered devices can fulfil device-based
    MFA requirements without re-prompting

Key IOCs:
  - Device registered during or shortly after the suspected access window
  - Personal (Workplace-registered) device on an account that normally uses
    corporate-joined hardware
  - Non-compliant device that still authenticates successfully
  - Unmanaged device (not enrolled in MDM/Intune)
  - Device OS that does not match the organisation's standard fleet
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from cirrus.collectors.base import GRAPH_BASE, CollectorError, GraphCollector
from cirrus.utils.helpers import dt_to_odata

# Device fields to retrieve from the API
_DEVICE_SELECT = (
    "id,displayName,deviceId,registrationDateTime,"
    "approximateLastSignInDateTime,operatingSystem,operatingSystemVersion,"
    "trustType,isCompliant,isManaged,profileType,deviceOwnership,"
    "enrollmentType,managementType"
)

# trustType values and what they mean
# AzureAD      — Azure AD joined (corporate device)
# ServerAD     — Hybrid Azure AD joined (on-prem + cloud)
# Workplace    — Azure AD registered (personal / BYOD device)
_PERSONAL_TRUST_TYPES = frozenset({"Workplace"})


def _flag_device(device: dict, start_dt: datetime | None) -> list[str]:
    """
    Return IOC flag strings for a registered device record.

    Args:
        device:   The device dict from the Graph API.
        start_dt: Collection window start. Devices registered on or after
                  this date receive a RECENTLY_REGISTERED flag. Falls back
                  to 30 days ago if None.
    """
    flags: list[str] = []

    # Threshold for "recently registered"
    if start_dt is None:
        threshold = datetime.now(timezone.utc) - timedelta(days=30)
    else:
        threshold = start_dt

    # ── Recently registered ───────────────────────────────────────────────────
    reg_str = device.get("registrationDateTime") or ""
    if reg_str:
        try:
            reg_dt = datetime.fromisoformat(reg_str.replace("Z", "+00:00"))
            if reg_dt >= threshold:
                flags.append(f"RECENTLY_REGISTERED:{reg_str[:10]}")
        except ValueError:
            pass

    # ── Personal / BYOD device ────────────────────────────────────────────────
    trust_type = device.get("trustType") or ""
    if trust_type in _PERSONAL_TRUST_TYPES:
        flags.append(f"PERSONAL_DEVICE:{trust_type}")

    # ── Compliance state ──────────────────────────────────────────────────────
    is_managed = device.get("isManaged")
    is_compliant = device.get("isCompliant")

    if is_managed is False:
        flags.append("UNMANAGED_DEVICE")
    elif is_managed is True and is_compliant is False:
        # Managed but explicitly non-compliant — Intune enrolled but failing policy
        flags.append("NON_COMPLIANT")

    return flags


class RegisteredDevicesCollector(GraphCollector):
    name = "registered_devices"

    def collect(
        self,
        users: list[str] | None = None,
        start_dt: datetime | None = None,
    ) -> list[dict]:
        """
        Collect registered devices.

        When users are specified, queries each user's registered devices
        individually — this is the appropriate mode for ATO investigations
        targeting known compromised accounts.

        When users is None, queries the tenant-wide /devices endpoint,
        optionally filtered to devices registered on or after start_dt.

        Args:
            users:    UPNs to query. None = tenant-wide collection.
            start_dt: Collection window start. Used to filter tenant-wide
                      queries and to set the RECENTLY_REGISTERED threshold.

        Returns list of device dicts, each annotated with _iocFlags and
        a _sourceUser field identifying which account the device belongs to.
        """
        results: list[dict] = []

        if users:
            # Per-user mode: fetch every device registered to each target account
            for upn in users:
                try:
                    devices = self._collect_all(
                        f"{GRAPH_BASE}/users/{upn}/registeredDevices",
                        params={"$select": _DEVICE_SELECT, "$top": 999},
                    )
                    for device in devices:
                        device["_sourceUser"] = upn
                        device["_iocFlags"] = _flag_device(device, start_dt)
                    results.extend(devices)
                except CollectorError as e:
                    if "404" not in str(e):
                        results.append({
                            "_sourceUser": upn,
                            "_error": str(e),
                            "_iocFlags": [],
                        })
        else:
            # Tenant-wide mode: query /devices, optionally filtered by date
            params: dict[str, Any] = {
                "$select": _DEVICE_SELECT,
                "$top": 999,
            }
            if start_dt is not None:
                params["$filter"] = f"registrationDateTime ge {dt_to_odata(start_dt)}"
                params["$count"] = "true"

            devices = self._collect_all(f"{GRAPH_BASE}/devices", params)
            for device in devices:
                device["_iocFlags"] = _flag_device(device, start_dt)
            results.extend(devices)

        return results
