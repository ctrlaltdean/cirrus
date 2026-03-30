"""
Tests for cirrus/collectors/sp_signin_logs.py

Covers:
  - _flag_sp_signin() IOC flag logic
  - _detect_auth_failures() cross-record high-failure detection
  - SPSignInLogsCollector.collect() pagination and license check
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from cirrus.collectors.sp_signin_logs import (
    SPSignInLogsCollector,
    _detect_auth_failures,
    _flag_sp_signin,
)


# ── _flag_sp_signin ────────────────────────────────────────────────────────────

class TestFlagSpSignin:
    def _rec(self, **kwargs) -> dict:
        return {
            "status": {"errorCode": 0},
            "servicePrincipalCredentialType": "",
            "ipAddress": "",
            "resourceId": "",
            "resourceDisplayName": "",
            "location": {},
            "managedIdentityType": None,
            **kwargs,
        }

    def test_no_flags_on_clean_record(self):
        assert _flag_sp_signin(self._rec()) == []

    def test_failed_auth_flag(self):
        rec = self._rec(status={"errorCode": 70011, "failureReason": "AADSTS70011"})
        flags = _flag_sp_signin(rec)
        assert any(f.startswith("FAILED_SP_AUTH:") for f in flags)

    def test_failed_auth_uses_error_code_fallback(self):
        rec = self._rec(status={"errorCode": 50034})
        flags = _flag_sp_signin(rec)
        assert "FAILED_SP_AUTH:errorCode=50034" in flags

    def test_client_secret_credential(self):
        rec = self._rec(servicePrincipalCredentialType="clientSecret")
        flags = _flag_sp_signin(rec)
        assert "CLIENT_SECRET_CREDENTIAL" in flags

    def test_certificate_credential(self):
        rec = self._rec(servicePrincipalCredentialType="Certificate")
        flags = _flag_sp_signin(rec)
        assert "CERTIFICATE_CREDENTIAL" in flags

    def test_public_ip_flagged(self):
        rec = self._rec(ipAddress="8.8.8.8")
        flags = _flag_sp_signin(rec)
        assert "PUBLIC_IP:8.8.8.8" in flags

    def test_private_ip_not_flagged(self):
        for ip in ("10.0.0.1", "192.168.1.1", "172.16.0.5", "127.0.0.1"):
            rec = self._rec(ipAddress=ip)
            flags = _flag_sp_signin(rec)
            assert not any(f.startswith("PUBLIC_IP:") for f in flags)

    def test_sensitive_resource_by_id(self):
        rec = self._rec(
            resourceId="00000003-0000-0000-c000-000000000000",
            resourceDisplayName="Microsoft Graph",
        )
        flags = _flag_sp_signin(rec)
        assert any(f.startswith("SENSITIVE_RESOURCE:") for f in flags)

    def test_sensitive_resource_by_name(self):
        rec = self._rec(
            resourceId="",
            resourceDisplayName="Microsoft Graph",
        )
        flags = _flag_sp_signin(rec)
        assert any(f.startswith("SENSITIVE_RESOURCE:") for f in flags)

    def test_non_sensitive_resource_not_flagged(self):
        rec = self._rec(
            resourceId="11111111-1111-1111-1111-111111111111",
            resourceDisplayName="My Internal App",
        )
        flags = _flag_sp_signin(rec)
        assert not any(f.startswith("SENSITIVE_RESOURCE:") for f in flags)

    def test_country_tagged(self):
        rec = self._rec(location={"countryOrRegion": "RU"})
        flags = _flag_sp_signin(rec)
        assert "COUNTRY:RU" in flags

    def test_managed_identity_flagged(self):
        rec = self._rec(managedIdentityType="SystemAssigned")
        flags = _flag_sp_signin(rec)
        assert "MANAGED_IDENTITY:SystemAssigned" in flags


# ── _detect_auth_failures ──────────────────────────────────────────────────────

class TestDetectAuthFailures:
    def _make_records(self, n_failures: int, app_id: str = "app-1") -> list[dict]:
        records = []
        for i in range(n_failures):
            rec = {
                "appId": app_id,
                "_iocFlags": [f"FAILED_SP_AUTH:reason_{i}"],
            }
            records.append(rec)
        return records

    def test_high_failure_rate_flag_added(self):
        records = self._make_records(10, "app-1")
        _detect_auth_failures(records)
        assert all(
            any(f.startswith("HIGH_FAILURE_RATE:") for f in r["_iocFlags"])
            for r in records
        )

    def test_below_threshold_not_flagged(self):
        records = self._make_records(9, "app-2")
        _detect_auth_failures(records)
        assert not any(
            any(f.startswith("HIGH_FAILURE_RATE:") for f in r["_iocFlags"])
            for r in records
        )

    def test_two_apps_only_high_failure_app_flagged(self):
        bad = self._make_records(10, "bad-app")
        good = self._make_records(3, "good-app")
        all_records = bad + good
        _detect_auth_failures(all_records)
        for r in bad:
            assert any(f.startswith("HIGH_FAILURE_RATE:") for f in r["_iocFlags"])
        for r in good:
            assert not any(f.startswith("HIGH_FAILURE_RATE:") for f in r["_iocFlags"])

    def test_success_records_not_counted(self):
        # Records without FAILED_SP_AUTH should not count toward the threshold
        records = [{"appId": "app-3", "_iocFlags": []} for _ in range(15)]
        _detect_auth_failures(records)
        assert not any(
            any(f.startswith("HIGH_FAILURE_RATE:") for f in r["_iocFlags"])
            for r in records
        )


# ── SPSignInLogsCollector ──────────────────────────────────────────────────────

class TestSPSignInLogsCollector:
    def _make_collector(self) -> SPSignInLogsCollector:
        collector = SPSignInLogsCollector.__new__(SPSignInLogsCollector)
        session = MagicMock()
        collector.session = session
        collector.license_profile = MagicMock()
        collector.license_profile.allows.return_value = True
        collector.on_status = None
        collector.on_page = None
        collector.token_provider = None
        return collector

    def _page(self, records: list[dict]) -> dict:
        return {"value": records}

    def test_collect_annotates_records_with_ioc_flags(self):
        collector = self._make_collector()
        raw = [
            {
                "status": {"errorCode": 0},
                "servicePrincipalCredentialType": "clientSecret",
                "ipAddress": "8.8.8.8",
                "resourceId": "",
                "resourceDisplayName": "My App",
                "location": {"countryOrRegion": "US"},
                "managedIdentityType": None,
            }
        ]
        with patch.object(collector, "_collect_all", return_value=raw):
            records = collector.collect(days=7)

        assert len(records) == 1
        flags = records[0]["_iocFlags"]
        assert "CLIENT_SECRET_CREDENTIAL" in flags
        assert "PUBLIC_IP:8.8.8.8" in flags
        assert "COUNTRY:US" in flags

    def test_collect_requires_p1_license(self):
        from cirrus.collectors.base import CollectorError
        collector = self._make_collector()
        collector.license_profile.allows.return_value = False

        with pytest.raises(CollectorError, match="P1"):
            collector.collect(days=7)

    def test_collect_with_date_range(self):
        from datetime import datetime, timezone
        collector = self._make_collector()
        start = datetime(2026, 3, 1, tzinfo=timezone.utc)
        end   = datetime(2026, 3, 15, tzinfo=timezone.utc)

        with patch.object(collector, "_collect_all", return_value=[]) as mock_ca:
            collector.collect(start_dt=start, end_dt=end)

        call_params = mock_ca.call_args[0][1]
        filt = call_params["$filter"]
        assert "ge 2026-03-01" in filt
        assert "le 2026-03-15" in filt

    def test_collect_filters_by_app_ids(self):
        collector = self._make_collector()
        with patch.object(collector, "_collect_all", return_value=[]) as mock_ca:
            collector.collect(app_ids=["app-guid-1", "app-guid-2"])

        call_params = mock_ca.call_args[0][1]
        filt = call_params["$filter"]
        assert "app-guid-1" in filt
        assert "app-guid-2" in filt

    def test_high_failure_rate_detected_end_to_end(self):
        collector = self._make_collector()
        raw = [
            {
                "appId": "bad-app",
                "status": {"errorCode": 70011, "failureReason": "bad creds"},
                "servicePrincipalCredentialType": "",
                "ipAddress": "",
                "resourceId": "",
                "resourceDisplayName": "",
                "location": {},
                "managedIdentityType": None,
            }
            for _ in range(10)
        ]
        with patch.object(collector, "_collect_all", return_value=raw):
            records = collector.collect(days=7)

        assert all(
            any(f.startswith("HIGH_FAILURE_RATE:") for f in r["_iocFlags"])
            for r in records
        )
