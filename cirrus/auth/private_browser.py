"""
Private/incognito browser launcher for MSAL interactive auth.

MSAL calls webbrowser.open() internally. This module temporarily patches
that call to open the auth URL in a private/incognito window instead, then
restores the original behaviour when done.

Supports: Edge (InPrivate), Chrome (Incognito), Firefox (Private Window),
          Chromium. Falls back to the default browser if none are found.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import webbrowser
from contextlib import contextmanager
from pathlib import Path


def _find_private_browser() -> tuple[list[str], str] | tuple[None, None]:
    """
    Search for a browser that supports a private/incognito flag.

    Returns (cmd_parts, flag) where cmd_parts is the base command list
    (may be a multi-word path on Windows) and flag is the private-mode arg,
    or (None, None) if no supported browser is found.
    """
    system = platform.system()

    if system == "Windows":
        return _find_windows()
    elif system == "Darwin":
        return _find_macos()
    else:
        return _find_linux()


# ---------------------------------------------------------------------------
# Platform finders
# ---------------------------------------------------------------------------

def _find_windows() -> tuple[list[str], str] | tuple[None, None]:
    # Explicit install paths — browsers usually aren't on PATH on Windows
    edge_paths = [
        Path(os.environ.get("ProgramFiles(x86)", ""), r"Microsoft\Edge\Application\msedge.exe"),
        Path(os.environ.get("ProgramFiles", ""),       r"Microsoft\Edge\Application\msedge.exe"),
    ]
    chrome_paths = [
        Path(os.environ.get("ProgramFiles", ""),        r"Google\Chrome\Application\chrome.exe"),
        Path(os.environ.get("ProgramFiles(x86)", ""),   r"Google\Chrome\Application\chrome.exe"),
        Path(os.environ.get("LOCALAPPDATA", ""),        r"Google\Chrome\Application\chrome.exe"),
    ]
    firefox_paths = [
        Path(os.environ.get("ProgramFiles", ""),        r"Mozilla Firefox\firefox.exe"),
        Path(os.environ.get("ProgramFiles(x86)", ""),   r"Mozilla Firefox\firefox.exe"),
    ]

    for path in edge_paths:
        if path.exists():
            return [str(path)], "--inprivate"

    for path in chrome_paths:
        if path.exists():
            return [str(path)], "--incognito"

    for path in firefox_paths:
        if path.exists():
            return [str(path)], "-private-window"

    # Fallback: try PATH (works if browser is portable or custom PATH is set)
    for exe, flag in [("msedge", "--inprivate"), ("chrome", "--incognito"), ("firefox", "-private-window")]:
        if shutil.which(exe):
            return [exe], flag

    return None, None


def _find_macos() -> tuple[list[str], str] | tuple[None, None]:
    # macOS: use `open -na "AppName" --args <flag>` to pass args to a .app bundle
    app_candidates = [
        ("Microsoft Edge",  "--inprivate"),
        ("Google Chrome",   "--incognito"),
        ("Firefox",         "-private-window"),
        ("Chromium",        "--incognito"),
    ]
    for app_name, flag in app_candidates:
        result = subprocess.run(
            ["osascript", "-e", f'POSIX path of (path to application "{app_name}")'],
            capture_output=True, text=True,
        )
        if result.returncode == 0 and result.stdout.strip():
            return ["open", "-na", app_name, "--args"], flag

    return None, None


def _find_linux() -> tuple[list[str], str] | tuple[None, None]:
    candidates = [
        ("microsoft-edge",          "--inprivate"),
        ("microsoft-edge-stable",   "--inprivate"),
        ("google-chrome",           "--incognito"),
        ("google-chrome-stable",    "--incognito"),
        ("chromium",                "--incognito"),
        ("chromium-browser",        "--incognito"),
        ("firefox",                 "-private-window"),
    ]
    for exe, flag in candidates:
        if shutil.which(exe):
            return [exe], flag

    return None, None


# ---------------------------------------------------------------------------
# Context manager
# ---------------------------------------------------------------------------

@contextmanager
def private_browser_auth():
    """
    Context manager that patches webbrowser.open() to launch a private window.

    Usage:
        with private_browser_auth() as is_private:
            result = app.acquire_token_interactive(...)

    Yields True if a private-mode browser was found, False if falling back
    to the normal default browser.
    """
    cmd_parts, flag = _find_private_browser()

    if not cmd_parts:
        yield False
        return

    original_open = webbrowser.open

    def _open_private(url: str, new: int = 0, autoraise: bool = True) -> bool:
        try:
            subprocess.Popen(
                cmd_parts + [flag, url],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
        except Exception:
            # If the private launch fails, fall back to the normal browser
            return original_open(url, new=new, autoraise=autoraise)

    webbrowser.open = _open_private
    try:
        yield True
    finally:
        webbrowser.open = original_open
