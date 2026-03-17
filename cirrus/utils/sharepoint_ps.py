"""
SharePoint Online PowerShell runner.

Executes SPO cmdlets from Python by spawning a PowerShell subprocess.
Requires: PowerShell 7+ and the Microsoft.Online.SharePoint.PowerShell module.
  Install: pwsh -Command "Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser -Force"

The SharePoint admin URL is: https://<tenantname>-admin.sharepoint.com
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass, field

from cirrus.utils.exchange_ps import find_powershell


def check_spo_module_installed(ps_path: str) -> tuple[bool, str]:
    """Check if Microsoft.Online.SharePoint.PowerShell module is installed."""
    try:
        result = subprocess.run(
            [
                ps_path, "-NonInteractive", "-NoProfile", "-Command",
                "Get-Module Microsoft.Online.SharePoint.PowerShell -ListAvailable | "
                "Sort-Object Version -Descending | "
                "Select-Object -First 1 -ExpandProperty Version | "
                "ForEach-Object { $_.ToString() }",
            ],
            capture_output=True, text=True, timeout=30,
        )
        version = result.stdout.strip()
        if result.returncode == 0 and version:
            return True, version
        return False, ""
    except Exception:
        return False, ""


@dataclass
class SharePointPSResults:
    """Holds the results of a SharePoint Online PowerShell batch collection."""
    available: bool = False
    error: str = ""
    spo_version: str = ""

    spo_tenant: dict = field(default_factory=dict)


def run_sharepoint_batch(spo_admin_url: str, upn: str | None = None) -> SharePointPSResults:
    """
    Connect to SharePoint Online and collect tenant configuration.
    Returns SharePointPSResults. On any failure, available=False with error details.
    """
    results = SharePointPSResults()

    ps_path = find_powershell()
    if not ps_path:
        results.error = "PowerShell not found."
        return results

    is_installed, spo_version = check_spo_module_installed(ps_path)
    if not is_installed:
        results.error = "Microsoft.Online.SharePoint.PowerShell module not installed. Run: cirrus deps install"
        return results

    results.spo_version = spo_version

    script = r"""
$ErrorActionPreference = 'Stop'
try {
    Import-Module Microsoft.Online.SharePoint.PowerShell -ErrorAction Stop -WarningAction SilentlyContinue

    $_spoArgs = @{ Url = $env:CIRRUS_SPO_ADMIN_URL; ErrorAction = 'Stop' }
    if ($env:CIRRUS_SPO_UPN) { $_spoArgs['Credential'] = $null }
    Connect-SPOService @_spoArgs

    $result = [ordered]@{}

    try {
        $t = Get-SPOTenant | Select-Object `
            SharingCapability, OneDriveSharingCapability, DefaultSharingLinkType,
            LegacyAuthProtocolsEnabled, RequireAcceptingAccountMatchInvitedAccount,
            PreventExternalUsersFromResharing
        $result.spo_tenant = $t
    } catch { $result.spo_tenant = @{ Error = $_.Exception.Message } }

    Disconnect-SPOService -ErrorAction SilentlyContinue | Out-Null

    $result | ConvertTo-Json -Depth 6 -Compress

} catch {
    $errMsg = $_.Exception.Message
    @{ __error = $errMsg } | ConvertTo-Json -Compress
    exit 1
}
"""

    try:
        proc = subprocess.run(
            [ps_path, "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            timeout=300,
            env={
                **os.environ,
                "CIRRUS_SPO_ADMIN_URL": spo_admin_url,
                "CIRRUS_SPO_UPN": upn or "",
            },
        )
    except subprocess.TimeoutExpired:
        results.error = "SharePoint Online PowerShell timed out (5 min)."
        return results
    except Exception as e:
        results.error = f"Failed to launch PowerShell: {e}"
        return results

    stdout = proc.stdout.strip()
    stderr = proc.stderr.strip()

    if not stdout:
        results.error = f"No output from SPO PS. stderr: {stderr[:500]}"
        return results

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        results.error = f"Could not parse SPO PS output. stdout: {stdout[:200]}"
        return results

    if "__error" in data:
        results.error = f"SPO PS error: {data['__error']}"
        return results

    results.available = True
    results.spo_tenant = data.get("spo_tenant") or {}

    return results


def derive_spo_admin_url(tenant_prefix: str) -> str:
    """Derive the SPO admin URL from the tenant prefix (e.g. 'contoso' -> 'https://contoso-admin.sharepoint.com')."""
    return f"https://{tenant_prefix}-admin.sharepoint.com"
