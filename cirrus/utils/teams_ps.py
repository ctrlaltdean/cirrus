"""
Microsoft Teams PowerShell runner.

Executes Teams cmdlets from Python by spawning a PowerShell subprocess.
Requires: PowerShell 7+ and the MicrosoftTeams module.
  Install: pwsh -Command "Install-Module MicrosoftTeams -Scope CurrentUser -Force"
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass, field
from typing import Any

from cirrus.utils.exchange_ps import find_powershell


def check_teams_module_installed(ps_path: str) -> tuple[bool, str]:
    """Check if MicrosoftTeams module is installed. Returns (is_installed, version)."""
    try:
        result = subprocess.run(
            [
                ps_path, "-NonInteractive", "-NoProfile", "-Command",
                "Get-Module MicrosoftTeams -ListAvailable | "
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
class TeamsPSResults:
    """Holds the results of a Teams PowerShell batch collection."""
    available: bool = False
    error: str = ""
    teams_version: str = ""

    federation_config: dict = field(default_factory=dict)
    meeting_policy_global: dict = field(default_factory=dict)
    guest_calling_config: dict = field(default_factory=dict)
    guest_meeting_config: dict = field(default_factory=dict)
    guest_messaging_config: dict = field(default_factory=dict)


def run_teams_batch(upn: str | None = None) -> TeamsPSResults:
    """
    Connect to Microsoft Teams and collect configuration data.
    Returns TeamsPSResults. On any failure, available=False with error details.
    """
    results = TeamsPSResults()

    ps_path = find_powershell()
    if not ps_path:
        results.error = "PowerShell not found."
        return results

    is_installed, teams_version = check_teams_module_installed(ps_path)
    if not is_installed:
        results.error = "MicrosoftTeams module not installed. Run: cirrus deps install"
        return results

    results.teams_version = teams_version

    script = r"""
$ErrorActionPreference = 'Stop'
try {
    Import-Module MicrosoftTeams -ErrorAction Stop
    $_teamsArgs = @{ ErrorAction = 'Stop' }
    if ($env:CIRRUS_TEAMS_UPN) { $_teamsArgs['AccountId'] = $env:CIRRUS_TEAMS_UPN }
    Connect-MicrosoftTeams @_teamsArgs | Out-Null

    $result = [ordered]@{}

    # Federation / External Access config
    try {
        $fed = Get-CsTenantFederationConfiguration
        $result.federation = @{
            AllowFederatedUsers     = $fed.AllowFederatedUsers
            AllowPublicUsers        = $fed.AllowPublicUsers
            AllowedDomainsIsAll     = ($fed.AllowedDomains.ToString() -match "AllowAllKnownDomains")
            AllowedDomainCount      = @($fed.AllowedDomains).Count
            BlockAllExternalDomains = $fed.BlockAllExternalDomains
        }
    } catch { $result.federation = @{ Error = $_.Exception.Message } }

    # Global meeting policy
    try {
        $mp = Get-CsTeamsMeetingPolicy -Identity Global
        $result.meeting_policy = @{
            AllowAnonymousUsersToJoinMeeting  = $mp.AllowAnonymousUsersToJoinMeeting
            AllowAnonymousUsersToStartMeeting = $mp.AllowAnonymousUsersToStartMeeting
        }
    } catch { $result.meeting_policy = @{ Error = $_.Exception.Message } }

    # Guest calling config
    try {
        $gc = Get-CsTeamsGuestCallingConfiguration
        $result.guest_calling = @{ AllowPrivateCalling = $gc.AllowPrivateCalling }
    } catch { $result.guest_calling = @{ Error = $_.Exception.Message } }

    # Guest meeting config
    try {
        $gm = Get-CsTeamsGuestMeetingConfiguration
        $result.guest_meeting = @{
            AllowIPVideo    = $gm.AllowIPVideo
            AllowMeetNow    = $gm.AllowMeetNow
            ScreenSharingMode = $gm.ScreenSharingMode
        }
    } catch { $result.guest_meeting = @{ Error = $_.Exception.Message } }

    # Guest messaging config
    try {
        $gmsg = Get-CsTeamsGuestMessagingConfiguration
        $result.guest_messaging = @{
            AllowChat                = $gmsg.AllowChat
            AllowDeleteSentMessages  = $gmsg.AllowDeleteSentMessages
            AllowEditSentMessages    = $gmsg.AllowEditSentMessages
            AllowGiphy               = $gmsg.AllowGiphy
            AllowStickers            = $gmsg.AllowStickers
            AllowMeetNow             = $gmsg.AllowMeetNow
        }
    } catch { $result.guest_messaging = @{ Error = $_.Exception.Message } }

    Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue | Out-Null

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
            env={**os.environ, "CIRRUS_TEAMS_UPN": upn or ""},
        )
    except subprocess.TimeoutExpired:
        results.error = "Teams PowerShell timed out (5 min)."
        return results
    except Exception as e:
        results.error = f"Failed to launch PowerShell: {e}"
        return results

    stdout = proc.stdout.strip()
    stderr = proc.stderr.strip()

    if not stdout:
        results.error = f"No output from Teams PS. stderr: {stderr[:500]}"
        return results

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        results.error = f"Could not parse Teams PS output. stdout: {stdout[:200]}"
        return results

    if "__error" in data:
        results.error = f"Teams PS error: {data['__error']}"
        return results

    results.available = True
    results.federation_config = data.get("federation") or {}
    results.meeting_policy_global = data.get("meeting_policy") or {}
    results.guest_calling_config = data.get("guest_calling") or {}
    results.guest_meeting_config = data.get("guest_meeting") or {}
    results.guest_messaging_config = data.get("guest_messaging") or {}

    return results
