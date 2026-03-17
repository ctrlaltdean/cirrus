"""
Exchange Online PowerShell runner.

Executes Exchange Online Management cmdlets from Python by spawning a
PowerShell subprocess. All cmdlets run in a single EXO session to avoid
repeated authentication prompts.

Requirements (detected at runtime, not hard dependencies):
  - PowerShell 7+  (pwsh)
  - ExchangeOnlineManagement module v3+
    Install: pwsh -Command "Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force"

Auth: uses Connect-ExchangeOnline with the analyst's UPN.
  - On enterprise machines with SSO, this is typically silent.
  - On first run or without SSO, the EXO module opens a browser for auth.

Results are stored in PolicyContext so each compliance check reads from
the cached data rather than making individual PS calls.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# PowerShell detection
# ---------------------------------------------------------------------------

def find_powershell() -> str | None:
    """Return the path to PowerShell 7 (pwsh), or PowerShell 5 on Windows fallback."""
    # Prefer pwsh (cross-platform PS 7)
    pwsh = shutil.which("pwsh")
    if pwsh:
        return pwsh
    # Fallback: Windows PowerShell 5 (windows only, but EXO v3 works with it)
    if sys.platform == "win32":
        ps = shutil.which("powershell")
        if ps:
            return ps
    return None


def check_exa_module_installed(ps_path: str) -> tuple[bool, str]:
    """
    Check if the ExchangeOnlineManagement module is installed.
    Returns (is_installed, version_string).
    """
    try:
        result = subprocess.run(
            [
                ps_path, "-NonInteractive", "-NoProfile", "-Command",
                "Get-Module ExchangeOnlineManagement -ListAvailable | "
                "Sort-Object Version -Descending | "
                "Select-Object -First 1 -ExpandProperty Version | "
                "ForEach-Object { $_.ToString() }",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        version = result.stdout.strip()
        if result.returncode == 0 and version:
            return True, version
        return False, ""
    except Exception:
        return False, ""


# ---------------------------------------------------------------------------
# Batch runner
# ---------------------------------------------------------------------------

@dataclass
class ExchangePSResults:
    """Holds the results of a batch Exchange Online PS collection."""
    available: bool = False
    error: str = ""
    ps_version: str = ""
    exa_version: str = ""

    anti_phish_policies: list[dict] = field(default_factory=list)
    safe_links_policies: list[dict] = field(default_factory=list)
    safe_attachments_policies: list[dict] = field(default_factory=list)
    outbound_spam_policies: list[dict] = field(default_factory=list)
    external_in_outlook: dict = field(default_factory=dict)
    org_config: dict = field(default_factory=dict)
    dkim_signing_configs: list[dict] = field(default_factory=list)
    admin_audit_log_config: dict = field(default_factory=dict)
    audit_retention_policies: list[dict] = field(default_factory=list)


def run_exchange_batch(tenant: str, upn: str | None = None) -> ExchangePSResults:
    """
    Connect to Exchange Online and collect all data needed for compliance checks
    in a single PowerShell session.

    Args:
        tenant: The tenant domain or GUID (e.g. contoso.com).
        upn:    Optional UPN hint for Connect-ExchangeOnline.
                If None, EXO module will determine auth from environment.

    Returns ExchangePSResults. On any failure, available=False with error details.
    """
    results = ExchangePSResults()

    ps_path = find_powershell()
    if not ps_path:
        results.error = "PowerShell not found. Install PowerShell 7: https://aka.ms/install-powershell"
        return results

    is_installed, exa_version = check_exa_module_installed(ps_path)
    if not is_installed:
        results.error = (
            "ExchangeOnlineManagement module not installed. "
            "Run: cirrus deps install"
        )
        return results

    results.exa_version = exa_version

    # Build connect command using env vars (avoids f-string in PS script)
    connect_cmd = "$_connectArgs = @{ ShowBanner = $false; ErrorAction = 'Stop' }\n"
    connect_cmd += "if ($env:CIRRUS_EXO_UPN) { $_connectArgs['UserPrincipalName'] = $env:CIRRUS_EXO_UPN }\n"
    connect_cmd += "Connect-ExchangeOnline @_connectArgs"

    # Single PowerShell script that connects once and runs all cmdlets,
    # outputting a JSON object with all results.
    # Uses environment variable for tenant to avoid injection.
    script = r"""
$ErrorActionPreference = 'Stop'
try {
    Import-Module ExchangeOnlineManagement -ErrorAction Stop
    """ + connect_cmd + r"""

    $result = [ordered]@{}

    # Anti-phishing policies
    try {
        $result.anti_phish = @(Get-AntiPhishPolicy | Select-Object Name,Enabled,
            EnableTargetedUserProtection,EnableMailboxIntelligence,
            EnableMailboxIntelligenceProtection,EnableOrganizationDomainsProtection,
            MailboxIntelligenceProtectionAction,TargetedUserProtectionAction,
            ImpersonationProtectionState)
    } catch { $result.anti_phish = @() }

    # Safe Links policies
    try {
        $result.safe_links = @(Get-SafeLinksPolicy | Select-Object Name,IsEnabled,
            TrackClicks,AllowClickThrough,EnableForInternalSenders,
            ScanUrls,EnableSafeLinksForEmail,EnableSafeLinksForTeams)
    } catch { $result.safe_links = @() }

    # Safe Attachments policies
    try {
        $result.safe_attachments = @(Get-SafeAttachmentPolicy | Select-Object Name,
            Enable,Action,ActionOnError,Redirect,RedirectAddress)
    } catch { $result.safe_attachments = @() }

    # Outbound spam / auto-forwarding
    try {
        $result.outbound_spam = @(Get-HostedOutboundSpamFilterPolicy | Select-Object Name,
            AutoForwardingMode,RecipientLimitExternalPerHour,RecipientLimitInternalPerHour)
    } catch { $result.outbound_spam = @() }

    # External sender identification (External In Outlook)
    try {
        $eio = Get-ExternalInOutlook
        $result.external_in_outlook = @{ Enabled = $eio.Enabled }
    } catch { $result.external_in_outlook = @{ Enabled = $null; Error = $_.Exception.Message } }

    # Organization config (modern auth, audit)
    try {
        $oc = Get-OrganizationConfig | Select-Object OAuth2ClientProfileEnabled,AuditDisabled,
            DefaultAuthenticationPolicy,IsDehydrated
        $result.org_config = $oc
    } catch { $result.org_config = @{} }

    # DKIM Signing Configs
    try {
        $result.dkim_signing = @(Get-DkimSigningConfig | Select-Object Domain, Enabled, Status)
    } catch { $result.dkim_signing = @() }

    # Admin Audit Log Config (includes UAL ingestion status)
    try {
        $alc = Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled, AdminAuditLogEnabled
        $result.admin_audit_log = $alc
    } catch { $result.admin_audit_log = @{ Error = $_.Exception.Message } }

    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null

    # Security & Compliance (IPPS) — audit log retention policies
    # Connect-IPPSSession is provided by the same ExchangeOnlineManagement module
    try {
        $_ippsArgs = @{ ShowBanner = $false; ErrorAction = 'Stop' }
        if ($env:CIRRUS_EXO_UPN) { $_ippsArgs['UserPrincipalName'] = $env:CIRRUS_EXO_UPN }
        Connect-IPPSSession @_ippsArgs
        try {
            $result.audit_retention = @(Get-UnifiedAuditLogRetentionPolicy | Select-Object Name, RetentionDuration, RecordTypes, Priority)
        } catch {
            $result.audit_retention = @(@{ Error = $_.Exception.Message })
        }
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    } catch {
        $result.audit_retention = @(@{ ConnectError = "IPPS connection failed: " + $_.Exception.Message })
    }

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
            timeout=300,  # 5 min — allows time for browser auth on first run
            env={**os.environ, "CIRRUS_EXO_TENANT": tenant, "CIRRUS_EXO_UPN": upn or ""},
        )
    except subprocess.TimeoutExpired:
        results.error = "Exchange Online PowerShell timed out (5 min). Check your network connection."
        return results
    except Exception as e:
        results.error = f"Failed to launch PowerShell: {e}"
        return results

    stdout = proc.stdout.strip()
    stderr = proc.stderr.strip()

    if not stdout:
        results.error = f"No output from PowerShell. stderr: {stderr[:500]}"
        return results

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        results.error = f"Could not parse PowerShell output. stdout: {stdout[:200]}"
        return results

    if "__error" in data:
        results.error = f"Exchange Online error: {data['__error']}"
        return results

    # Parse each section
    results.available = True
    results.anti_phish_policies = _ensure_list(data.get("anti_phish", []))
    results.safe_links_policies = _ensure_list(data.get("safe_links", []))
    results.safe_attachments_policies = _ensure_list(data.get("safe_attachments", []))
    results.outbound_spam_policies = _ensure_list(data.get("outbound_spam", []))
    results.external_in_outlook = data.get("external_in_outlook") or {}
    results.org_config = data.get("org_config") or {}
    results.dkim_signing_configs = _ensure_list(data.get("dkim_signing", []))
    results.admin_audit_log_config = data.get("admin_audit_log") or {}
    results.audit_retention_policies = _ensure_list(data.get("audit_retention", []))

    return results


def _ensure_list(val: Any) -> list[dict]:
    """Normalize a PS output value to a list of dicts."""
    if val is None:
        return []
    if isinstance(val, list):
        return val
    if isinstance(val, dict):
        return [val]
    return []
