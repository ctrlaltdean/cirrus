"""
Unit tests for _validate_upn() in cli.py.

This function was the source of a critical inversion bug (v0.4.19).
Convention: returns None when valid, error string when invalid.
"""

from __future__ import annotations

import pytest

from cirrus.cli import _validate_upn


# ── Valid UPNs — must return None ──────────────────────────────────────────────

class TestValidUPNs:
    @pytest.mark.parametrize("upn", [
        "alice@contoso.com",
        "bob.smith@contoso.onmicrosoft.com",
        "admin@tenant.co.uk",
        "user+tag@company.org",
        "first.last@subdomain.contoso.com",
        "A@B.C",  # minimal valid form
        "svc-account@contoso.com",
        "user123@contoso.com",
    ])
    def test_valid_upn_returns_none(self, upn: str):
        result = _validate_upn(upn)
        assert result is None, f"Expected None for valid UPN {upn!r}, got: {result!r}"


# ── Invalid UPNs — must return an error string ─────────────────────────────────

class TestInvalidUPNs:
    def test_no_at_sign_is_invalid(self):
        result = _validate_upn("notaupn")
        assert result is not None
        assert isinstance(result, str)

    def test_two_at_signs_is_invalid(self):
        result = _validate_upn("a@@b.com")
        assert result is not None

    def test_leading_at_sign_empty_local(self):
        result = _validate_upn("@contoso.com")
        assert result is not None

    def test_domain_without_dot_is_invalid(self):
        result = _validate_upn("user@contoso")
        assert result is not None
        assert "." in result or "domain" in result.lower()

    def test_space_in_upn_is_invalid(self):
        result = _validate_upn("alice smith@contoso.com")
        assert result is not None
        assert "space" in result.lower() or "space" in result

    def test_space_at_start_is_invalid(self):
        result = _validate_upn(" alice@contoso.com")
        assert result is not None

    def test_space_at_end_is_invalid(self):
        result = _validate_upn("alice@contoso.com ")
        assert result is not None

    def test_empty_string_is_invalid(self):
        result = _validate_upn("")
        assert result is not None


# ── Return type contract ───────────────────────────────────────────────────────

class TestReturnTypeContract:
    def test_valid_upn_returns_exactly_none(self):
        assert _validate_upn("user@contoso.com") is None

    def test_invalid_upn_returns_non_empty_string(self):
        result = _validate_upn("notvalid")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_callers_must_use_if_err_not_if_value(self):
        """
        Regression guard for the v0.4.19 bug where callers used `if v:` instead
        of `if err:`. A valid UPN must return a falsy value (None), and an invalid
        UPN must return a truthy value (non-empty string).
        """
        valid_result = _validate_upn("user@contoso.com")
        assert not valid_result, "Valid UPN must return falsy (None)"

        invalid_result = _validate_upn("badupn")
        assert invalid_result, "Invalid UPN must return truthy (error string)"
