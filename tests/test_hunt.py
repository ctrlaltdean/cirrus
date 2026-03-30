"""
Tests for cirrus/analysis/hunt.py

Covers:
  - HuntTarget / HuntReport dataclass properties
  - _hunt_signin_anomalies()
  - _hunt_new_admin_accounts()
  - _hunt_oauth_risky_apps()
  - _hunt_password_spray()
  - run_hunt() orchestration and error handling
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from cirrus.analysis.hunt import (
    HuntReport,
    HuntSignal,
    HuntTarget,
    _hunt_new_admin_accounts,
    _hunt_oauth_risky_apps,
    _hunt_password_spray,
    _hunt_signin_anomalies,
    run_hunt,
)


# ── Dataclass properties ───────────────────────────────────────────────────────

class TestHuntTarget:
    def _target(self, severities: list[str]) -> HuntTarget:
        signals = [HuntSignal("check", sev, "detail") for sev in severities]
        return HuntTarget(name="user@test.com", target_type="user", signals=signals)

    def test_signal_count(self):
        t = self._target(["high", "medium"])
        assert t.signal_count == 2

    def test_max_severity_high(self):
        assert self._target(["medium", "high"]).max_severity == "high"

    def test_max_severity_medium(self):
        assert self._target(["medium", "low"]).max_severity == "medium"

    def test_max_severity_low(self):
        assert self._target(["low"]).max_severity == "low"

    def test_max_severity_empty(self):
        assert self._target([]).max_severity == "low"


class TestHuntReport:
    def _report(self, targets: list[HuntTarget]) -> HuntReport:
        return HuntReport(tenant="test.com", days=30, generated_at="2026-03-30T00:00:00Z", targets=targets)

    def _make_target(self, sev: str, signal_count: int = 1) -> HuntTarget:
        signals = [HuntSignal("chk", sev, "d") for _ in range(signal_count)]
        return HuntTarget(name="u", target_type="user", signals=signals)

    def test_high_targets_filter(self):
        r = self._report([self._make_target("high"), self._make_target("medium")])
        assert len(r.high_targets) == 1
        assert r.high_targets[0].max_severity == "high"

    def test_total_signals(self):
        r = self._report([self._make_target("high", 3), self._make_target("medium", 2)])
        assert r.total_signals == 5

    def test_empty_report(self):
        r = self._report([])
        assert r.high_targets == []
        assert r.total_signals == 0


# ── _hunt_signin_anomalies ─────────────────────────────────────────────────────

class TestHuntSigninAnomalies:
    def _session(self) -> MagicMock:
        return MagicMock()

    def _start_dt(self):
        from datetime import datetime, timezone
        from datetime import timedelta
        return datetime.now(timezone.utc) - timedelta(days=7)

    def _make_collect(self, records: list[dict]):
        def _fake_collect_all(session, url, params=None, max_records=5000):
            return records
        return _fake_collect_all

    def test_device_code_flagged_as_high(self):
        records = [{"userPrincipalName": "user@test.com",
                    "authenticationProtocol": "deviceCode",
                    "clientAppUsed": "",
                    "location": {},
                    "riskLevelAggregated": "none",
                    "riskState": "",
                    "createdDateTime": "2026-03-28T10:00:00Z"}]
        with patch("cirrus.analysis.hunt._collect_all", self._make_collect(records)):
            targets, err = _hunt_signin_anomalies(self._session(), self._start_dt())

        assert err is None
        assert len(targets) == 1
        assert targets[0].max_severity == "high"
        assert any("deviceCode" in s.detail for s in targets[0].signals)

    def test_legacy_auth_flagged_as_medium(self):
        records = [{"userPrincipalName": "user@test.com",
                    "authenticationProtocol": "",
                    "clientAppUsed": "IMAP4",
                    "location": {},
                    "riskLevelAggregated": "",
                    "riskState": "",
                    "createdDateTime": "2026-03-28T10:00:00Z"}]
        with patch("cirrus.analysis.hunt._collect_all", self._make_collect(records)):
            targets, err = _hunt_signin_anomalies(self._session(), self._start_dt())

        assert err is None
        assert len(targets) == 1
        assert targets[0].signals[0].severity == "medium"

    def test_impossible_travel_flagged(self):
        records = [
            {"userPrincipalName": "user@test.com",
             "authenticationProtocol": "",
             "clientAppUsed": "",
             "location": {"countryOrRegion": "US"},
             "riskLevelAggregated": "",
             "riskState": "",
             "createdDateTime": "2026-03-28T10:00:00Z"},
            {"userPrincipalName": "user@test.com",
             "authenticationProtocol": "",
             "clientAppUsed": "",
             "location": {"countryOrRegion": "RU"},
             "riskLevelAggregated": "",
             "riskState": "",
             "createdDateTime": "2026-03-28T10:30:00Z"},
        ]
        with patch("cirrus.analysis.hunt._collect_all", self._make_collect(records)):
            targets, err = _hunt_signin_anomalies(self._session(), self._start_dt())

        assert err is None
        assert len(targets) == 1
        assert any("Impossible travel" in s.detail for s in targets[0].signals)

    def test_no_impossible_travel_same_country(self):
        records = [
            {"userPrincipalName": "user@test.com", "authenticationProtocol": "",
             "clientAppUsed": "", "location": {"countryOrRegion": "US"},
             "riskLevelAggregated": "", "riskState": "",
             "createdDateTime": "2026-03-28T10:00:00Z"},
            {"userPrincipalName": "user@test.com", "authenticationProtocol": "",
             "clientAppUsed": "", "location": {"countryOrRegion": "US"},
             "riskLevelAggregated": "", "riskState": "",
             "createdDateTime": "2026-03-28T10:30:00Z"},
        ]
        with patch("cirrus.analysis.hunt._collect_all", self._make_collect(records)):
            targets, err = _hunt_signin_anomalies(self._session(), self._start_dt())
        assert targets == []

    def test_permission_error_returns_error_string(self):
        def _raise(*a, **kw):
            raise PermissionError("403")
        with patch("cirrus.analysis.hunt._collect_all", _raise):
            targets, err = _hunt_signin_anomalies(self._session(), self._start_dt())
        assert targets == []
        assert err is not None

    def test_clean_records_return_empty_targets(self):
        records = [{"userPrincipalName": "user@test.com",
                    "authenticationProtocol": "",
                    "clientAppUsed": "",
                    "location": {},
                    "riskLevelAggregated": "",
                    "riskState": "",
                    "createdDateTime": "2026-03-28T10:00:00Z"}]
        with patch("cirrus.analysis.hunt._collect_all", self._make_collect(records)):
            targets, err = _hunt_signin_anomalies(self._session(), self._start_dt())
        assert targets == []
        assert err is None


# ── _hunt_oauth_risky_apps ─────────────────────────────────────────────────────

class TestHuntOauthRiskyApps:
    def _session(self) -> MagicMock:
        return MagicMock()

    def test_high_risk_scope_multi_user_flagged(self):
        grants = [
            {"clientId": "app-1", "scope": "Mail.Read Files.Read.All",
             "principalId": "user-1", "consentType": "Principal"},
            {"clientId": "app-1", "scope": "Mail.Read",
             "principalId": "user-2", "consentType": "Principal"},
        ]

        def _fake_collect(session, url, params=None, max_records=5000):
            if "servicePrincipals" in url:
                return [{"displayName": "Evil App", "appId": "app-1"}]
            return grants

        with patch("cirrus.analysis.hunt._collect_all", _fake_collect):
            targets, err = _hunt_oauth_risky_apps(self._session())

        assert err is None
        assert len(targets) == 1
        assert targets[0].target_type == "app"
        assert any("Mail.Read" in s.detail for s in targets[0].signals)

    def test_admin_consent_allusers_is_high_severity(self):
        grants = [
            {"clientId": "app-2", "scope": "Directory.Read.All",
             "principalId": None, "consentType": "AllUsers"},
        ]

        def _fake_collect(session, url, params=None, max_records=5000):
            if "servicePrincipals" in url:
                return []
            return grants

        with patch("cirrus.analysis.hunt._collect_all", _fake_collect):
            targets, err = _hunt_oauth_risky_apps(self._session())

        assert err is None
        assert len(targets) == 1
        assert targets[0].signals[0].severity == "high"
        assert "all users" in targets[0].signals[0].detail

    def test_low_risk_scope_not_flagged(self):
        grants = [
            {"clientId": "app-3", "scope": "User.Read Calendars.Read",
             "principalId": "user-1", "consentType": "Principal"},
            {"clientId": "app-3", "scope": "User.Read",
             "principalId": "user-2", "consentType": "Principal"},
        ]

        def _fake_collect(session, url, params=None, max_records=5000):
            if "servicePrincipals" in url:
                return []
            return grants

        with patch("cirrus.analysis.hunt._collect_all", _fake_collect):
            targets, err = _hunt_oauth_risky_apps(self._session())

        assert targets == []

    def test_single_user_high_risk_not_flagged(self):
        # One user consenting to a high-risk scope: below _RISKY_APP_MIN_USERS
        grants = [
            {"clientId": "app-4", "scope": "Mail.Read",
             "principalId": "user-1", "consentType": "Principal"},
        ]

        def _fake_collect(session, url, params=None, max_records=5000):
            if "servicePrincipals" in url:
                return []
            return grants

        with patch("cirrus.analysis.hunt._collect_all", _fake_collect):
            targets, err = _hunt_oauth_risky_apps(self._session())

        assert targets == []


# ── _hunt_password_spray ───────────────────────────────────────────────────────

class TestHuntPasswordSpray:
    def _start_dt(self):
        from datetime import datetime, timezone, timedelta
        return datetime.now(timezone.utc) - timedelta(days=7)

    def _make_records(self, ip: str, n_targets: int, n_failures: int,
                      include_success: bool = False) -> list[dict]:
        records = []
        for i in range(n_failures):
            upn = f"user{i % n_targets}@test.com"
            records.append({"userPrincipalName": upn, "ipAddress": ip,
                             "status": {"errorCode": 50034},
                             "createdDateTime": "2026-03-28T10:00:00Z"})
        if include_success:
            records.append({"userPrincipalName": "victim@test.com", "ipAddress": ip,
                             "status": {"errorCode": 0},
                             "createdDateTime": "2026-03-28T11:00:00Z"})
        return records

    def test_spray_detected_medium(self):
        records = self._make_records("1.2.3.4", n_targets=5, n_failures=10)

        def _fake_collect(session, url, params=None, max_records=5000):
            return records

        with patch("cirrus.analysis.hunt._collect_all", _fake_collect):
            targets, err = _hunt_password_spray(MagicMock(), self._start_dt())

        assert err is None
        assert len(targets) == 1
        assert targets[0].signals[0].severity == "medium"

    def test_spray_with_success_elevated_to_high(self):
        records = self._make_records("5.6.7.8", n_targets=5, n_failures=10, include_success=True)

        def _fake_collect(session, url, params=None, max_records=5000):
            return records

        with patch("cirrus.analysis.hunt._collect_all", _fake_collect):
            targets, err = _hunt_password_spray(MagicMock(), self._start_dt())

        assert err is None
        assert len(targets) == 1
        assert targets[0].signals[0].severity == "high"

    def test_too_few_targets_not_flagged(self):
        records = self._make_records("9.9.9.9", n_targets=4, n_failures=10)

        def _fake_collect(session, url, params=None, max_records=5000):
            return records

        with patch("cirrus.analysis.hunt._collect_all", _fake_collect):
            targets, err = _hunt_password_spray(MagicMock(), self._start_dt())

        assert targets == []

    def test_too_few_failures_not_flagged(self):
        records = self._make_records("2.3.4.5", n_targets=5, n_failures=9)

        def _fake_collect(session, url, params=None, max_records=5000):
            return records

        with patch("cirrus.analysis.hunt._collect_all", _fake_collect):
            targets, err = _hunt_password_spray(MagicMock(), self._start_dt())

        assert targets == []

    def test_private_ip_excluded(self):
        records = self._make_records("192.168.1.1", n_targets=5, n_failures=10)

        def _fake_collect(session, url, params=None, max_records=5000):
            return records

        with patch("cirrus.analysis.hunt._collect_all", _fake_collect):
            targets, err = _hunt_password_spray(MagicMock(), self._start_dt())

        assert targets == []


# ── run_hunt orchestration ─────────────────────────────────────────────────────

class TestRunHunt:
    def test_run_hunt_returns_report(self):
        def _fake_signin(session, start_dt):
            return ([HuntTarget("u@t.com", "user", [HuntSignal("s", "high", "d")])], None)
        def _fake_admin(session, start_dt):
            return ([], None)
        def _fake_oauth(session):
            return ([], None)
        def _fake_spray(session, start_dt):
            return ([], None)

        with (
            patch("cirrus.analysis.hunt._hunt_signin_anomalies", _fake_signin),
            patch("cirrus.analysis.hunt._hunt_new_admin_accounts", _fake_admin),
            patch("cirrus.analysis.hunt._hunt_oauth_risky_apps", _fake_oauth),
            patch("cirrus.analysis.hunt._hunt_password_spray", _fake_spray),
        ):
            report = run_hunt(token="tok", days=7, tenant="test.com")

        assert isinstance(report, HuntReport)
        assert len(report.targets) == 1
        assert report.targets[0].max_severity == "high"

    def test_run_hunt_aggregates_signals_for_same_account(self):
        t1 = HuntTarget("user@test.com", "user", [HuntSignal("s1", "high", "device code")])
        t2 = HuntTarget("user@test.com", "user", [HuntSignal("s2", "medium", "new admin")])

        def _fake_signin(session, start_dt):
            return ([t1], None)
        def _fake_admin(session, start_dt):
            return ([t2], None)
        def _fake_oauth(session):
            return ([], None)
        def _fake_spray(session, start_dt):
            return ([], None)

        with (
            patch("cirrus.analysis.hunt._hunt_signin_anomalies", _fake_signin),
            patch("cirrus.analysis.hunt._hunt_new_admin_accounts", _fake_admin),
            patch("cirrus.analysis.hunt._hunt_oauth_risky_apps", _fake_oauth),
            patch("cirrus.analysis.hunt._hunt_password_spray", _fake_spray),
        ):
            report = run_hunt(token="tok", days=7)

        assert len(report.targets) == 1
        assert report.targets[0].signal_count == 2

    def test_run_hunt_collects_errors(self):
        def _fake_signin(session, start_dt):
            return ([], "signin_anomalies: 403")
        def _fake_admin(session, start_dt):
            return ([], None)
        def _fake_oauth(session):
            return ([], None)
        def _fake_spray(session, start_dt):
            return ([], None)

        with (
            patch("cirrus.analysis.hunt._hunt_signin_anomalies", _fake_signin),
            patch("cirrus.analysis.hunt._hunt_new_admin_accounts", _fake_admin),
            patch("cirrus.analysis.hunt._hunt_oauth_risky_apps", _fake_oauth),
            patch("cirrus.analysis.hunt._hunt_password_spray", _fake_spray),
        ):
            report = run_hunt(token="tok", days=7)

        assert any("signin_anomalies" in e for e in report.errors)

    def test_run_hunt_sorted_by_severity_then_signal_count(self):
        high2 = HuntTarget("h2@t.com", "user", [HuntSignal("s", "high", "d"), HuntSignal("s", "high", "d2")])
        high1 = HuntTarget("h1@t.com", "user", [HuntSignal("s", "high", "d")])
        med   = HuntTarget("m@t.com",  "user", [HuntSignal("s", "medium", "d")])

        def _fake_signin(session, start_dt):
            return ([high1, med, high2], None)
        def _noop_dt(session, start_dt):
            return ([], None)
        def _noop(session):
            return ([], None)

        with (
            patch("cirrus.analysis.hunt._hunt_signin_anomalies", _fake_signin),
            patch("cirrus.analysis.hunt._hunt_new_admin_accounts", _noop_dt),
            patch("cirrus.analysis.hunt._hunt_oauth_risky_apps", _noop),
            patch("cirrus.analysis.hunt._hunt_password_spray", _noop_dt),
        ):
            report = run_hunt(token="tok", days=7)

        names = [t.name for t in report.targets]
        assert names[0] == "h2@t.com"   # high, 2 signals
        assert names[1] == "h1@t.com"   # high, 1 signal
        assert names[2] == "m@t.com"    # medium
