"""Shared utility helpers."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path


def utc_now() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def utc_now_dt() -> datetime:
    """Return current UTC datetime."""
    return datetime.now(timezone.utc)


def slugify(value: str) -> str:
    """Convert a string to a safe filename slug."""
    value = re.sub(r"[^\w\s.-]", "", value)
    value = re.sub(r"[\s]+", "_", value)
    return value.strip("._")


def file_sha256(path: Path) -> str:
    """Return the SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_user_list(
    user: str | None,
    users: list[str] | None,
    users_file: str | None,
) -> list[str] | None:
    """
    Merge user targeting options into a single list.
    Returns None to indicate "all users".
    """
    result: list[str] = []

    if user:
        result.append(user.strip())

    if users:
        result.extend(u.strip() for u in users if u.strip())

    if users_file:
        path = Path(users_file)
        if not path.exists():
            raise FileNotFoundError(f"Users file not found: {users_file}")
        lines = path.read_text().splitlines()
        result.extend(line.strip() for line in lines if line.strip() and not line.startswith("#"))

    return result if result else None


def days_ago_filter(days: int) -> str:
    """Return an OData datetime filter string for N days ago (ISO-8601)."""
    from datetime import timedelta
    dt = datetime.now(timezone.utc) - timedelta(days=days)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
