"""
CIRRUS self-update utility.

Checks the GitHub Releases API for a newer version and downloads the
appropriate platform binary to replace the running executable.

Only functional when running as a PyInstaller bundle (sys.frozen == True).
When run from source, reports that updates should be done via git pull.
"""

from __future__ import annotations

import os
import platform
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import requests

from cirrus import __version__

GITHUB_OWNER = "ctrlaltdean"
GITHUB_REPO  = "cirrus"
RELEASES_API = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/releases/latest"

# Asset names published by the GitHub Actions build workflow
_PLATFORM_ASSET: dict[str, str] = {
    "Windows": "cirrus-windows-x64.exe",
    "Darwin":  "cirrus-macos-x64",
    "Linux":   "cirrus-linux-x64",
}


@dataclass
class UpdateInfo:
    current_version: str
    latest_version:  str
    update_available: bool
    download_url:    str | None = None
    asset_name:      str | None = None
    release_notes:   str | None = None
    error:           str | None = None


def is_frozen() -> bool:
    """True when running as a PyInstaller bundle."""
    return getattr(sys, "frozen", False)


def check_for_update() -> UpdateInfo:
    """
    Query the GitHub Releases API.
    Returns UpdateInfo regardless of whether an update is available.
    """
    system     = platform.system()
    asset_name = _PLATFORM_ASSET.get(system)

    try:
        resp = requests.get(
            RELEASES_API,
            timeout=10,
            headers={"Accept": "application/vnd.github+json"},
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        return UpdateInfo(
            current_version=__version__,
            latest_version="unknown",
            update_available=False,
            asset_name=asset_name,
            error=str(exc),
        )

    latest_tag   = data.get("tag_name", "").lstrip("v")
    release_body = data.get("body", "").strip() or None
    download_url = None

    if asset_name:
        for asset in data.get("assets", []):
            if asset.get("name") == asset_name:
                download_url = asset.get("browser_download_url")
                break

    return UpdateInfo(
        current_version  = __version__,
        latest_version   = latest_tag,
        update_available = _is_newer(latest_tag, __version__),
        download_url     = download_url,
        asset_name       = asset_name,
        release_notes    = release_body,
    )


def apply_update(
    download_url: str,
    progress_callback: "Callable[[int, int], None] | None" = None,
) -> tuple[bool, str]:
    """
    Download the new binary and schedule replacement of the running executable.

    On Unix:   os.replace() works directly (files are not locked while running).
    On Windows: the running .exe is locked by the OS. We write a small detached
                batch script that waits for this process to exit, swaps the files,
                then deletes itself.

    Args:
        download_url:      Direct download URL for the new binary.
        progress_callback: Optional callable(bytes_downloaded, total_bytes).

    Returns:
        (success, message)
    """
    if not is_frozen():
        return False, "Self-update only works for the pre-built executable. Use 'git pull' instead."

    current_exe = Path(sys.executable)
    new_exe     = current_exe.with_suffix(".new" + current_exe.suffix)

    # --- Download ---
    try:
        resp = requests.get(download_url, stream=True, timeout=120)
        resp.raise_for_status()
        total = int(resp.headers.get("content-length", 0))
        downloaded = 0

        with open(new_exe, "wb") as fh:
            for chunk in resp.iter_content(chunk_size=65536):
                if chunk:
                    fh.write(chunk)
                    downloaded += len(chunk)
                    if progress_callback and total:
                        progress_callback(downloaded, total)
    except Exception as exc:
        new_exe.unlink(missing_ok=True)
        return False, f"Download failed: {exc}"

    # Make executable on Unix
    if platform.system() != "Windows":
        new_exe.chmod(new_exe.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    # --- Swap ---
    if platform.system() == "Windows":
        return _swap_windows(current_exe, new_exe)
    else:
        return _swap_unix(current_exe, new_exe)


# ---------------------------------------------------------------------------
# Internal: platform swap helpers
# ---------------------------------------------------------------------------

def _swap_unix(current_exe: Path, new_exe: Path) -> tuple[bool, str]:
    try:
        os.replace(new_exe, current_exe)
        return True, "Updated successfully. Restart CIRRUS to use the new version."
    except Exception as exc:
        new_exe.unlink(missing_ok=True)
        return False, f"Failed to replace executable: {exc}"


def _swap_windows(current_exe: Path, new_exe: Path) -> tuple[bool, str]:
    """
    The running .exe is locked on Windows. Write a batch script that:
      1. Waits a couple of seconds for the parent process to exit
      2. Moves new_exe → current_exe
      3. Deletes itself
    Then launches it as a detached process and returns.
    """
    bat_path = current_exe.with_suffix(".update.bat")
    bat_lines = [
        "@echo off",
        # Wait ~2 s for the parent to exit (ping to localhost is a portable sleep trick)
        "ping -n 3 127.0.0.1 >NUL",
        f'move /Y "{new_exe}" "{current_exe}"',
        'del "%~f0"',
    ]
    try:
        bat_path.write_text("\r\n".join(bat_lines) + "\r\n", encoding="ascii")
    except Exception as exc:
        new_exe.unlink(missing_ok=True)
        return False, f"Failed to write update script: {exc}"

    try:
        subprocess.Popen(
            ["cmd.exe", "/c", str(bat_path)],
            creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
            close_fds=True,
        )
    except Exception as exc:
        bat_path.unlink(missing_ok=True)
        new_exe.unlink(missing_ok=True)
        return False, f"Failed to launch update script: {exc}"

    return (
        True,
        "Update downloaded. CIRRUS will finish updating after this window closes.\n"
        "Restart CIRRUS to use the new version.",
    )


# ---------------------------------------------------------------------------
# Version comparison
# ---------------------------------------------------------------------------

def _is_newer(latest: str, current: str) -> bool:
    """Return True if latest > current (semver-style tuple comparison)."""
    try:
        def _parts(v: str) -> tuple[int, ...]:
            return tuple(int(x) for x in v.strip().split("."))
        return _parts(latest) > _parts(current)
    except (ValueError, AttributeError):
        return False
