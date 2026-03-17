"""
Dependency checker and auto-installer for CIRRUS optional components.

Checks for and optionally installs:
  - dnspython                    (Python package, pip install)
  - PowerShell 7                 (pwsh binary — platform installer)
  - ExchangeOnlineManagement     (PS module, Install-Module)

This module never raises on import — missing deps are reported, not fatal.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from enum import Enum


class DepStatus(Enum):
    OK = "ok"
    MISSING = "missing"
    ERROR = "error"


@dataclass
class DepResult:
    name: str
    status: DepStatus
    version: str = ""
    message: str = ""
    install_hint: str = ""

    @property
    def ok(self) -> bool:
        return self.status == DepStatus.OK


# ---------------------------------------------------------------------------
# Individual dependency checks
# ---------------------------------------------------------------------------

def check_dnspython() -> DepResult:
    """Check if dnspython is installed."""
    try:
        import importlib.metadata
        version = importlib.metadata.version("dnspython")
        return DepResult(name="dnspython", status=DepStatus.OK, version=version,
                         message="DNS checks (DMARC, SPF, DKIM) are available.")
    except Exception:
        return DepResult(
            name="dnspython",
            status=DepStatus.MISSING,
            message="Required for DNS-based compliance checks (DMARC, SPF, DKIM).",
            install_hint="cirrus deps install  (or: pip install dnspython)",
        )


def check_powershell() -> DepResult:
    """Check if PowerShell 7 (pwsh) or PowerShell 5 is available."""
    from cirrus.utils.exchange_ps import find_powershell
    ps = find_powershell()
    if not ps:
        return DepResult(
            name="PowerShell",
            status=DepStatus.MISSING,
            message="Required for Exchange Online compliance checks.",
            install_hint="https://aka.ms/install-powershell  (install PowerShell 7)",
        )
    try:
        result = subprocess.run(
            [ps, "-NonInteractive", "-NoProfile", "-Command",
             "$PSVersionTable.PSVersion.ToString()"],
            capture_output=True, text=True, timeout=15,
        )
        version = result.stdout.strip() or "(detected)"
    except Exception:
        version = "(detected)"
    return DepResult(
        name="PowerShell", status=DepStatus.OK, version=version,
        message=f"Found at: {ps}",
    )


def check_exo_module() -> DepResult:
    """Check if ExchangeOnlineManagement PS module is installed."""
    from cirrus.utils.exchange_ps import check_exa_module_installed, find_powershell
    ps = find_powershell()
    if not ps:
        return DepResult(
            name="ExchangeOnlineManagement",
            status=DepStatus.MISSING,
            message="PowerShell not found — required to check EXO module.",
            install_hint="Install PowerShell 7 first: https://aka.ms/install-powershell",
        )
    is_installed, version = check_exa_module_installed(ps)
    if is_installed:
        return DepResult(
            name="ExchangeOnlineManagement", status=DepStatus.OK, version=version,
            message="Exchange Online compliance checks are available.",
        )
    return DepResult(
        name="ExchangeOnlineManagement",
        status=DepStatus.MISSING,
        message="Required for Exchange Online compliance checks.",
        install_hint='cirrus deps install  (or: pwsh -Command "Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force")',
    )


def check_all() -> list[DepResult]:
    """Run all dependency checks and return results."""
    return [
        check_dnspython(),
        check_powershell(),
        check_exo_module(),
    ]


# ---------------------------------------------------------------------------
# Installers
# ---------------------------------------------------------------------------

def install_dnspython() -> tuple[bool, str]:
    """Install dnspython via pip. Returns (success, message)."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "dnspython>=2.4"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0:
            return True, "dnspython installed successfully."
        return False, (result.stderr.strip() or result.stdout.strip() or "pip exited non-zero.")
    except subprocess.TimeoutExpired:
        return False, "pip install timed out (2 min)."
    except Exception as e:
        return False, str(e)


def install_exo_module() -> tuple[bool, str]:
    """Install ExchangeOnlineManagement module via PowerShell. Returns (success, message)."""
    from cirrus.utils.exchange_ps import find_powershell
    ps = find_powershell()
    if not ps:
        return False, "PowerShell not found. Install PowerShell 7 first: https://aka.ms/install-powershell"
    try:
        result = subprocess.run(
            [
                ps, "-NonInteractive", "-NoProfile", "-Command",
                "Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber",
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode == 0:
            return True, "ExchangeOnlineManagement module installed successfully."
        error = result.stderr.strip() or result.stdout.strip() or "PowerShell exited non-zero."
        return False, error
    except subprocess.TimeoutExpired:
        return False, "Module installation timed out (5 min). Try running manually:\n  pwsh -Command \"Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force\""
    except Exception as e:
        return False, str(e)


def install_all_missing(results: list[DepResult]) -> list[tuple[str, bool, str]]:
    """
    Install any missing installable dependencies.
    Returns list of (dep_name, success, message).
    """
    outcomes: list[tuple[str, bool, str]] = []

    for dep in results:
        if dep.ok:
            continue

        if dep.name == "dnspython":
            ok, msg = install_dnspython()
            outcomes.append(("dnspython", ok, msg))

        elif dep.name == "ExchangeOnlineManagement":
            ok, msg = install_exo_module()
            outcomes.append(("ExchangeOnlineManagement", ok, msg))

        elif dep.name == "PowerShell":
            # Can't auto-install PowerShell — guide the user
            outcomes.append((
                "PowerShell", False,
                "PowerShell must be installed manually.\n"
                "  Windows: winget install Microsoft.PowerShell\n"
                "  macOS:   brew install --cask powershell\n"
                "  Linux:   https://aka.ms/install-powershell",
            ))

    return outcomes
