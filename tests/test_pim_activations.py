"""
Tests for cirrus/collectors/pim_activations.py

Covers:
  - _flag_pim_record() IOC flag logic
  - _is_unusual_hour() time detection
  - PIMActivationsCollector.collect() with pagination, license check, user filter
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from cirrus.collectors.pim_activations import (
    PIMActivationsCollector,
    _flag_pim_record,
    _is_unusual_hour,
)


# ── _is_unusual_hour ───────────────────────────────────────────────────────────

class TestIsUnusualHour:
    def test_midnight_is_unusual(self):
        assert _is_unusual_hour("2026-03-28T00:30:00Z")

    def test_3am_is_unusual(self):
        assert _is_unusual_hour("2026-03-28T03:00:00Z")

    def test_11pm_is_unusual(self):
        assert _is_unusual_hour("2026-03-28T23:00:00Z")

    def test_noon_is_not_unusual(self):
        assert not _is_unusual_hour("2026-03-28T12:00:00Z")

    def test_9am_is_not_unusual(self):
        assert not _is_unusual_hour("2026-03-28T09:00:00Z")

    def test_empty_string_returns_false(self):
        assert not _is_unusual_hour("")

    def test_invalid_string_returns_false(self):
        assert not _is_unusual_hour("not-a-date")


# ── _flag_pim_record ───────────────────────────────────────────────────────────

class TestFlagPimRecord:
    def _rec(self, activity: str = "", ts: str = "2026-03-28T12:00:00Z",
             role_name: str = "", justification: str = "",
             initiator_upn: str = "", target_upn: str = "") -> dict:
        record: dict = {
            "activityDisplayName": activity,
            "activityDateTime": ts,
            "result": "success",
            "resultReason": "",
            "initiatedBy": {"user": {"userPrincipalName": initiator_upn}},
            "targetResources": [],
            "additionalDetails": [],
        }
        if role_name:
            record["additionalDetails"].append({"key": "roleName", "value": role_name})
        if justification:
            record["additionalDetails"].append({"key": "justification", "value": justification})
        if target_upn:
            record["targetResources"].append({"type": "User", "userPrincipalName": target_upn})
        return record

    def test_policy_change_flagged(self):
        rec = self._rec(activity="Update role setting in pim")
        flags = _flag_pim_record(rec)
        assert "PIM_POLICY_CHANGE" in flags

    def test_high_priv_activation_flagged(self):
        rec = self._rec(
            activity="Add member to role in pim completed",
            role_name="Global Administrator",
        )
        flags = _flag_pim_record(rec)
        assert any(f.startswith("HIGH_PRIV_PIM_ACTIVATION:") for f in flags)
        assert "PIM_ACTIVATION:Global Administrator" in flags

    def test_low_priv_activation_not_high_priv(self):
        rec = self._rec(
            activity="Add member to role in pim completed",
            role_name="Reports Reader",
        )
        flags = _flag_pim_record(rec)
        assert "PIM_ACTIVATION:Reports Reader" in flags
        assert not any(f.startswith("HIGH_PRIV_PIM_ACTIVATION:") for f in flags)

    def test_missing_justification_flagged(self):
        rec = self._rec(
            activity="Add member to role in pim completed",
            role_name="Security Reader",
            justification="",
        )
        flags = _flag_pim_record(rec)
        assert "JUSTIFICATION_MISSING" in flags

    def test_with_justification_not_flagged(self):
        rec = self._rec(
            activity="Add member to role in pim completed",
            role_name="Security Reader",
            justification="Investigating incident INC-12345",
        )
        flags = _flag_pim_record(rec)
        assert "JUSTIFICATION_MISSING" not in flags

    def test_unusual_hour_flagged(self):
        rec = self._rec(
            activity="Add member to role in pim completed",
            role_name="Security Reader",
            ts="2026-03-28T02:30:00Z",
        )
        flags = _flag_pim_record(rec)
        assert "ACTIVATION_OUTSIDE_HOURS" in flags

    def test_business_hours_not_flagged(self):
        rec = self._rec(
            activity="Add member to role in pim completed",
            role_name="Security Reader",
            ts="2026-03-28T14:00:00Z",
        )
        flags = _flag_pim_record(rec)
        assert "ACTIVATION_OUTSIDE_HOURS" not in flags

    def test_self_activation_flagged(self):
        rec = self._rec(
            activity="Add member to role in pim completed",
            role_name="Security Reader",
            initiator_upn="user@contoso.com",
            target_upn="user@contoso.com",
        )
        flags = _flag_pim_record(rec)
        assert "SELF_ACTIVATION" in flags

    def test_admin_activated_not_self(self):
        rec = self._rec(
            activity="Add member to role in pim completed",
            role_name="Security Reader",
            initiator_upn="admin@contoso.com",
            target_upn="user@contoso.com",
        )
        flags = _flag_pim_record(rec)
        assert "SELF_ACTIVATION" not in flags

    def test_non_activation_event_tagged_pim_event(self):
        rec = self._rec(activity="Remove member from role in pim")
        flags = _flag_pim_record(rec)
        assert "PIM_EVENT" in flags


# ── PIMActivationsCollector ────────────────────────────────────────────────────

class TestPIMActivationsCollector:
    def _make_collector(self) -> PIMActivationsCollector:
        collector = PIMActivationsCollector.__new__(PIMActivationsCollector)
        collector.session = MagicMock()
        collector.license_profile = MagicMock()
        collector.license_profile.allows.return_value = True
        collector.on_status = None
        collector.on_page = None
        collector.token_provider = None
        return collector

    def test_collect_annotates_records(self):
        collector = self._make_collector()
        raw = [{
            "activityDisplayName": "Add member to role in pim completed",
            "activityDateTime": "2026-03-28T12:00:00Z",
            "result": "success",
            "resultReason": "",
            "initiatedBy": {"user": {"userPrincipalName": "admin@contoso.com"}},
            "targetResources": [{"type": "User", "userPrincipalName": "user@contoso.com"}],
            "additionalDetails": [{"key": "roleName", "value": "Security Reader"}],
        }]
        with patch.object(collector, "_collect_all", return_value=raw):
            records = collector.collect(days=30)
        assert len(records) == 1
        assert any(f.startswith("PIM_ACTIVATION:") for f in records[0]["_iocFlags"])

    def test_collect_requires_p2(self):
        from cirrus.collectors.base import CollectorError
        collector = self._make_collector()
        collector.license_profile.allows.return_value = False
        with pytest.raises(CollectorError, match="P2"):
            collector.collect(days=30)

    def test_user_filter_applied(self):
        collector = self._make_collector()
        raw = [
            {
                "activityDisplayName": "Add member to role in pim completed",
                "activityDateTime": "2026-03-28T12:00:00Z",
                "result": "success",
                "resultReason": "",
                "initiatedBy": {"user": {"userPrincipalName": "alice@contoso.com"}},
                "targetResources": [{"type": "User", "userPrincipalName": "alice@contoso.com"}],
                "additionalDetails": [{"key": "roleName", "value": "Security Reader"}],
            },
            {
                "activityDisplayName": "Add member to role in pim completed",
                "activityDateTime": "2026-03-28T13:00:00Z",
                "result": "success",
                "resultReason": "",
                "initiatedBy": {"user": {"userPrincipalName": "bob@contoso.com"}},
                "targetResources": [{"type": "User", "userPrincipalName": "bob@contoso.com"}],
                "additionalDetails": [{"key": "roleName", "value": "Security Reader"}],
            },
        ]
        with patch.object(collector, "_collect_all", return_value=raw):
            records = collector.collect(days=30, users=["alice@contoso.com"])
        assert len(records) == 1
        assert records[0]["initiatedBy"]["user"]["userPrincipalName"] == "alice@contoso.com"

    def test_filter_uses_beta_endpoint(self):
        collector = self._make_collector()
        with patch.object(collector, "_collect_all", return_value=[]) as mock_ca:
            collector.collect(days=7)
        url = mock_ca.call_args[0][0]
        assert "beta" in url

    def test_pim_service_filter_in_params(self):
        collector = self._make_collector()
        with patch.object(collector, "_collect_all", return_value=[]) as mock_ca:
            collector.collect(days=7)
        filt = mock_ca.call_args[0][1]["$filter"]
        assert "PIM" in filt
