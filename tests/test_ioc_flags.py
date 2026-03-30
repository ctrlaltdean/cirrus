"""
Unit tests for sign-in IOC flag functions.

These test pure functions that do not touch the network or filesystem —
_flag_signin() and _detect_impossible_travel() in signin_logs.py.
"""

from __future__ import annotations

import pytest

from cirrus.collectors.signin_logs import _detect_impossible_travel, _flag_signin
from tests.conftest import make_signin


# ── _flag_signin: basic successful sign-in ─────────────────────────────────────

class TestFlagSigninClean:
    def test_no_flags_on_clean_record(self):
        r = make_signin(error_code=0, ip="203.0.113.1", country="US", city="Seattle")
        flags = _flag_signin(r)
        # Country and city tags always appear; no IOC flags
        assert "COUNTRY:US" in flags
        assert "CITY:Seattle" in flags
        # No problem flags
        problem = [f for f in flags if not f.startswith(("COUNTRY:", "CITY:", "PUBLIC_IP:"))]
        assert problem == []

    def test_public_ip_tagged(self):
        r = make_signin(ip="203.0.113.42")
        flags = _flag_signin(r)
        assert "PUBLIC_IP:203.0.113.42" in flags

    def test_private_ip_not_tagged(self):
        for private_ip in ("10.0.0.1", "192.168.1.50", "172.16.0.1", "127.0.0.1", "169.254.1.1"):
            r = make_signin(ip=private_ip)
            flags = _flag_signin(r)
            public_flags = [f for f in flags if f.startswith("PUBLIC_IP:")]
            assert public_flags == [], f"Private IP {private_ip} should not produce PUBLIC_IP flag"


# ── _flag_signin: failure cases ────────────────────────────────────────────────

class TestFlagSigninFailures:
    def test_failed_signin_errorcode_50126(self):
        r = make_signin(error_code=50126)
        r["status"]["failureReason"] = "Invalid username or password."
        flags = _flag_signin(r)
        failed = [f for f in flags if f.startswith("FAILED_SIGNIN:")]
        assert len(failed) == 1
        assert "Invalid username or password." in failed[0]

    def test_failed_signin_uses_errorcode_when_no_reason(self):
        r = make_signin(error_code=50053)
        r["status"]["failureReason"] = None
        flags = _flag_signin(r)
        failed = [f for f in flags if f.startswith("FAILED_SIGNIN:")]
        assert any("50053" in f for f in failed)

    def test_errorcode_zero_does_not_produce_failed_flag(self):
        r = make_signin(error_code=0)
        flags = _flag_signin(r)
        assert not any(f.startswith("FAILED_SIGNIN:") for f in flags)


# ── _flag_signin: legacy authentication ───────────────────────────────────────

class TestFlagSigninLegacyAuth:
    @pytest.mark.parametrize("client_app", [
        "Exchange ActiveSync",
        "IMAP4",
        "POP3",
        "SMTP",
        "MAPI",
        "Basic Authentication",
        "Basic Auth",
        "Authenticated SMTP",
        "Exchange Web Services",
    ])
    def test_legacy_auth_flagged(self, client_app: str):
        r = make_signin(client_app_used=client_app)
        flags = _flag_signin(r)
        assert any(f.startswith("LEGACY_AUTH:") for f in flags), (
            f"Expected LEGACY_AUTH flag for clientAppUsed={client_app!r}"
        )

    def test_modern_auth_browser_not_flagged(self):
        r = make_signin(client_app_used="Browser")
        flags = _flag_signin(r)
        assert not any(f.startswith("LEGACY_AUTH:") for f in flags)

    def test_modern_auth_mobile_app_not_flagged(self):
        r = make_signin(client_app_used="Mobile Apps and Desktop clients")
        flags = _flag_signin(r)
        assert not any(f.startswith("LEGACY_AUTH:") for f in flags)


# ── _flag_signin: suspicious auth protocols ───────────────────────────────────

class TestFlagSigninSuspiciousProtocol:
    def test_device_code_flagged(self):
        r = make_signin(auth_protocol="deviceCode")
        flags = _flag_signin(r)
        assert "SUSPICIOUS_AUTH_PROTOCOL:deviceCode" in flags

    def test_ropc_flagged(self):
        r = make_signin(auth_protocol="ropc")
        flags = _flag_signin(r)
        assert "SUSPICIOUS_AUTH_PROTOCOL:ropc" in flags

    def test_none_auth_protocol_not_flagged(self):
        r = make_signin(auth_protocol="none")
        flags = _flag_signin(r)
        assert not any(f.startswith("SUSPICIOUS_AUTH_PROTOCOL:") for f in flags)

    def test_empty_auth_protocol_not_flagged(self):
        r = make_signin(auth_protocol="")
        flags = _flag_signin(r)
        assert not any(f.startswith("SUSPICIOUS_AUTH_PROTOCOL:") for f in flags)


# ── _flag_signin: single-factor success ───────────────────────────────────────

class TestFlagSigninSingleFactor:
    def test_single_factor_success_flagged(self):
        r = make_signin(auth_req="singleFactorAuthentication", error_code=0)
        flags = _flag_signin(r)
        assert "SINGLE_FACTOR_SUCCESS" in flags

    def test_mfa_success_not_flagged(self):
        r = make_signin(auth_req="multiFactorAuthentication", error_code=0)
        flags = _flag_signin(r)
        assert "SINGLE_FACTOR_SUCCESS" not in flags

    def test_single_factor_failure_not_flagged(self):
        # Failed sign-in with single factor should NOT get SINGLE_FACTOR_SUCCESS
        r = make_signin(auth_req="singleFactorAuthentication", error_code=50126)
        flags = _flag_signin(r)
        assert "SINGLE_FACTOR_SUCCESS" not in flags


# ── _flag_signin: conditional access ─────────────────────────────────────────

class TestFlagSigninCA:
    def test_ca_failure_flagged(self):
        r = make_signin(ca_status="failure")
        flags = _flag_signin(r)
        assert "CA_POLICY_FAILURE" in flags

    def test_ca_success_not_flagged(self):
        r = make_signin(ca_status="success")
        flags = _flag_signin(r)
        assert "CA_POLICY_FAILURE" not in flags

    def test_ca_not_applied_not_flagged(self):
        r = make_signin(ca_status="notApplied")
        flags = _flag_signin(r)
        assert "CA_POLICY_FAILURE" not in flags


# ── _flag_signin: risk signals ────────────────────────────────────────────────

class TestFlagSigninRisk:
    def test_high_risk_level_flagged(self):
        r = make_signin(risk_level="high")
        flags = _flag_signin(r)
        assert "RISK_LEVEL:high" in flags

    def test_medium_risk_level_flagged(self):
        r = make_signin(risk_level="medium")
        flags = _flag_signin(r)
        assert "RISK_LEVEL:medium" in flags

    def test_no_risk_level_not_flagged(self):
        r = make_signin(risk_level="none")
        flags = _flag_signin(r)
        assert not any(f.startswith("RISK_LEVEL:") for f in flags)

    def test_at_risk_state_flagged(self):
        r = make_signin(risk_state="atRisk")
        flags = _flag_signin(r)
        assert "RISK_STATE:atRisk" in flags

    def test_confirmed_compromised_flagged(self):
        r = make_signin(risk_state="confirmedCompromised")
        flags = _flag_signin(r)
        assert "RISK_STATE:confirmedCompromised" in flags

    def test_dismissed_risk_state_not_flagged(self):
        r = make_signin(risk_state="dismissed")
        flags = _flag_signin(r)
        assert not any(f.startswith("RISK_STATE:") for f in flags)

    @pytest.mark.parametrize("risk_detail", [
        "anonymizedIPAddress",
        "maliciousIPAddress",
        "impossibleTravel",
        "newCountry",
        "unfamiliarFeatures",
        "malwareInfectedIPAddress",
    ])
    def test_geo_risk_details_flagged(self, risk_detail: str):
        r = make_signin(risk_detail=risk_detail)
        flags = _flag_signin(r)
        assert f"GEO_RISK:{risk_detail}" in flags

    @pytest.mark.parametrize("risk_detail", [
        "leakedCredentials",
        "investigationsThreatIntelligence",
        "adminConfirmedSigninCompromised",
        "anomalousToken",
        "tokenIssuerAnomaly",
    ])
    def test_identity_risk_details_flagged(self, risk_detail: str):
        r = make_signin(risk_detail=risk_detail)
        flags = _flag_signin(r)
        assert f"IDENTITY_RISK:{risk_detail}" in flags

    def test_no_risk_detail_not_flagged(self):
        r = make_signin(risk_detail="none")
        flags = _flag_signin(r)
        assert not any(f.startswith("GEO_RISK:") or f.startswith("IDENTITY_RISK:") for f in flags)

    def test_flagged_for_review(self):
        r = make_signin()
        r["flaggedForReview"] = True
        flags = _flag_signin(r)
        assert "FLAGGED_FOR_REVIEW" in flags

    def test_not_flagged_for_review(self):
        r = make_signin(flagged=False)
        flags = _flag_signin(r)
        assert "FLAGGED_FOR_REVIEW" not in flags


# ── _detect_impossible_travel ─────────────────────────────────────────────────

class TestDetectImpossibleTravel:
    def _run(self, records: list[dict]) -> None:
        for r in records:
            r.setdefault("_iocFlags", [])
        _detect_impossible_travel(records)

    def test_different_countries_within_window_flagged(self):
        r1 = make_signin(upn="alice@contoso.com", country="US", created="2026-01-15T08:00:00Z")
        r2 = make_signin(upn="alice@contoso.com", country="RU", created="2026-01-15T09:00:00Z")
        r1["_iocFlags"] = []
        r2["_iocFlags"] = []
        self._run([r1, r2])
        travel_flags = [f for f in r1["_iocFlags"] if f.startswith("IMPOSSIBLE_TRAVEL:")]
        assert travel_flags, "Expected IMPOSSIBLE_TRAVEL flag on r1"
        assert "US->RU" in travel_flags[0]

    def test_both_records_get_flag(self):
        r1 = make_signin(upn="bob@contoso.com", country="GB", created="2026-01-15T08:00:00Z")
        r2 = make_signin(upn="bob@contoso.com", country="CN", created="2026-01-15T09:30:00Z")
        r1["_iocFlags"] = []
        r2["_iocFlags"] = []
        self._run([r1, r2])
        assert any(f.startswith("IMPOSSIBLE_TRAVEL:") for f in r1["_iocFlags"])
        assert any(f.startswith("IMPOSSIBLE_TRAVEL:") for f in r2["_iocFlags"])

    def test_same_country_not_flagged(self):
        r1 = make_signin(upn="carol@contoso.com", country="US", created="2026-01-15T08:00:00Z")
        r2 = make_signin(upn="carol@contoso.com", country="US", created="2026-01-15T08:30:00Z")
        r1["_iocFlags"] = []
        r2["_iocFlags"] = []
        self._run([r1, r2])
        assert not any(f.startswith("IMPOSSIBLE_TRAVEL:") for f in r1["_iocFlags"])
        assert not any(f.startswith("IMPOSSIBLE_TRAVEL:") for f in r2["_iocFlags"])

    def test_different_countries_outside_window_not_flagged(self):
        # 5 hours apart — outside the 2-hour threshold
        r1 = make_signin(upn="dave@contoso.com", country="US", created="2026-01-15T00:00:00Z")
        r2 = make_signin(upn="dave@contoso.com", country="RU", created="2026-01-15T05:00:00Z")
        r1["_iocFlags"] = []
        r2["_iocFlags"] = []
        self._run([r1, r2])
        assert not any(f.startswith("IMPOSSIBLE_TRAVEL:") for f in r1["_iocFlags"])
        assert not any(f.startswith("IMPOSSIBLE_TRAVEL:") for f in r2["_iocFlags"])

    def test_different_users_not_cross_linked(self):
        r1 = make_signin(upn="eve@contoso.com", country="US", created="2026-01-15T08:00:00Z")
        r2 = make_signin(upn="frank@contoso.com", country="RU", created="2026-01-15T08:01:00Z")
        r1["_iocFlags"] = []
        r2["_iocFlags"] = []
        self._run([r1, r2])
        assert not any(f.startswith("IMPOSSIBLE_TRAVEL:") for f in r1["_iocFlags"])
        assert not any(f.startswith("IMPOSSIBLE_TRAVEL:") for f in r2["_iocFlags"])

    def test_empty_records_no_error(self):
        self._run([])  # should not raise

    def test_flag_includes_hour_delta(self):
        r1 = make_signin(upn="alice@contoso.com", country="US", created="2026-01-15T08:00:00Z")
        r2 = make_signin(upn="alice@contoso.com", country="DE", created="2026-01-15T09:30:00Z")
        r1["_iocFlags"] = []
        r2["_iocFlags"] = []
        self._run([r1, r2])
        travel = [f for f in r1["_iocFlags"] if f.startswith("IMPOSSIBLE_TRAVEL:")]
        assert travel
        assert "1.5h" in travel[0]
