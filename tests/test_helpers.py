"""
Unit tests for CIRRUS utility helper functions.

Tests cover pure functions and filesystem operations that do not require
a live tenant or network access.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from cirrus.utils.helpers import (
    file_sha256,
    is_private_ip,
    parse_user_list,
    slugify,
)


# ── is_private_ip ──────────────────────────────────────────────────────────────

class TestIsPrivateIp:
    @pytest.mark.parametrize("ip", [
        "10.0.0.1",
        "10.255.255.255",
        "192.168.0.1",
        "192.168.100.254",
        "172.16.0.1",
        "172.31.255.255",
        "127.0.0.1",
        "127.0.0.255",
        "169.254.0.1",
        "169.254.255.255",
    ])
    def test_private_ip_returns_true(self, ip: str):
        assert is_private_ip(ip) is True, f"{ip} should be private"

    @pytest.mark.parametrize("ip", [
        "203.0.113.1",    # TEST-NET-3 (public)
        "198.51.100.42",  # TEST-NET-2 (public)
        "8.8.8.8",        # Google DNS
        "1.1.1.1",        # Cloudflare
        "185.220.101.1",  # Tor exit node range
        "172.15.255.255", # just below 172.16/12
        "172.32.0.1",     # just above 172.31/12
    ])
    def test_public_ip_returns_false(self, ip: str):
        assert is_private_ip(ip) is False, f"{ip} should be public"

    def test_empty_string_returns_true(self):
        assert is_private_ip("") is True

    def test_none_like_value(self):
        assert is_private_ip("") is True


# ── file_sha256 ────────────────────────────────────────────────────────────────

class TestFileSha256:
    def test_known_hash(self, tmp_path: Path):
        content = b"hello cirrus"
        expected = hashlib.sha256(content).hexdigest()
        f = tmp_path / "test.txt"
        f.write_bytes(content)
        assert file_sha256(f) == expected

    def test_empty_file(self, tmp_path: Path):
        f = tmp_path / "empty.txt"
        f.write_bytes(b"")
        expected = hashlib.sha256(b"").hexdigest()
        assert file_sha256(f) == expected

    def test_different_content_different_hash(self, tmp_path: Path):
        f1 = tmp_path / "a.txt"
        f2 = tmp_path / "b.txt"
        f1.write_bytes(b"hello")
        f2.write_bytes(b"world")
        assert file_sha256(f1) != file_sha256(f2)

    def test_same_content_same_hash(self, tmp_path: Path):
        content = b"reproducible content"
        f1 = tmp_path / "c1.txt"
        f2 = tmp_path / "c2.txt"
        f1.write_bytes(content)
        f2.write_bytes(content)
        assert file_sha256(f1) == file_sha256(f2)

    def test_hash_is_hex_string(self, tmp_path: Path):
        f = tmp_path / "hex.txt"
        f.write_bytes(b"test")
        result = file_sha256(f)
        assert isinstance(result, str)
        assert len(result) == 64
        int(result, 16)  # must be valid hex


# ── slugify ────────────────────────────────────────────────────────────────────

class TestSlugify:
    def test_spaces_become_underscores(self):
        assert slugify("incident case 001") == "incident_case_001"

    def test_special_chars_removed(self):
        result = slugify("case: <active> [2026]")
        assert "<" not in result
        assert ">" not in result
        assert ":" not in result

    def test_alphanumeric_preserved(self):
        assert slugify("ABC123") == "ABC123"

    def test_dots_and_hyphens_preserved(self):
        result = slugify("INC-2026-001.log")
        assert "-" in result
        assert "." in result

    def test_leading_trailing_stripped(self):
        result = slugify("...hello...")
        assert not result.startswith(".")
        assert not result.endswith(".")

    def test_empty_string(self):
        result = slugify("")
        assert isinstance(result, str)


# ── parse_user_list ────────────────────────────────────────────────────────────

class TestParseUserList:
    def test_single_user(self):
        result = parse_user_list("alice@contoso.com", None, None)
        assert result == ["alice@contoso.com"]

    def test_multiple_users(self):
        result = parse_user_list(None, ["alice@contoso.com", "bob@contoso.com"], None)
        assert set(result) == {"alice@contoso.com", "bob@contoso.com"}

    def test_single_and_multiple_merged(self):
        result = parse_user_list(
            "alice@contoso.com",
            ["bob@contoso.com"],
            None,
        )
        assert "alice@contoso.com" in result
        assert "bob@contoso.com" in result

    def test_users_file(self, tmp_path: Path):
        f = tmp_path / "users.txt"
        f.write_text("alice@contoso.com\nbob@contoso.com\n# comment\n")
        result = parse_user_list(None, None, str(f))
        assert "alice@contoso.com" in result
        assert "bob@contoso.com" in result
        # Comment lines should be excluded
        assert not any(r.startswith("#") for r in result)

    def test_users_file_not_found_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            parse_user_list(None, None, str(tmp_path / "nonexistent.txt"))

    def test_all_none_returns_none(self):
        result = parse_user_list(None, None, None)
        assert result is None

    def test_whitespace_trimmed(self):
        result = parse_user_list("  alice@contoso.com  ", None, None)
        assert "alice@contoso.com" in result

    def test_empty_strings_excluded(self):
        result = parse_user_list(None, ["alice@contoso.com", "  ", ""], None)
        assert "" not in result
        assert "  " not in result
