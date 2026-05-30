# Copyright (c) 2026 FLINTEK LLC
# Licensed under the Apache License, Version 2.0.
# See LICENSE in the project root for license information.

"""Shared utility helpers."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime, timezone
from pathlib import Path

# Networks treated as "internal/infrastructure" — IOC flags are suppressed for
# these. Covers IPv4 RFC1918, loopback, link-local, and CGNAT, plus the IPv6
# equivalents (loopback, unique-local, link-local). Documentation/TEST-NET
# ranges are intentionally NOT included — they are treated as public so they
# still surface for analyst review.
_PRIVATE_NETWORKS: tuple[ipaddress._BaseNetwork, ...] = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "100.64.0.0/10",   # CGNAT (RFC 6598)
        "::1/128",         # IPv6 loopback
        "fc00::/7",        # IPv6 unique-local
        "fe80::/10",       # IPv6 link-local
    )
)


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


def dt_to_odata(dt: datetime) -> str:
    """Format a UTC datetime as an OData-compatible ISO-8601 string."""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def is_private_ip(ip: str) -> bool:
    """
    Return True if the IP address is internal/infrastructure and should not be
    enriched or IOC-flagged: RFC1918, loopback, link-local, CGNAT, or their
    IPv6 equivalents (unique-local, link-local, loopback).

    Unparseable or empty values are treated as private (True) so collectors
    suppress them rather than emit noise. Documentation/TEST-NET ranges are
    treated as public.
    """
    if not ip:
        return True
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return True
    return any(addr in net for net in _PRIVATE_NETWORKS)
