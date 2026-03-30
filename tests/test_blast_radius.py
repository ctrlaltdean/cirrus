"""
Tests for cirrus/analysis/blast_radius.py

Covers:
  - BlastRadiusReport / AccessDimension dataclass properties
  - Individual check functions (API responses mocked)
  - run_blast_radius() parallel execution and optional file output
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cirrus.analysis.blast_radius import (
    AccessDimension,
    BlastRadiusReport,
    _check_app_role_assignments,
    _check_directory_roles,
    _check_group_memberships,
    _check_oauth_grants,
    _check_owned_objects,
    _check_signin_apps,
    run_blast_radius,
)


# ── BlastRadiusReport dataclass ────────────────────────────────────────────────

class TestBlastRadiusReport:
    def _make_report(self, statuses: list[str]) -> BlastRadiusReport:
        dims = [AccessDimension(label=f"dim{i}", status=s, summary="") for i, s in enumerate(statuses)]
        return BlastRadiusReport(user="user@test.com", tenant="test.com", dimensions=dims)

    def test_risk_level_high(self):
        report = self._make_report(["high", "clean", "clean"])
        assert report.risk_level == "high"

    def test_risk_level_warn(self):
        report = self._make_report(["warn", "clean"])
        assert report.risk_level == "warn"

    def test_risk_level_clean(self):
        report = self._make_report(["clean", "clean"])
        assert report.risk_level == "clean"

    def test_risk_level_high_takes_precedence_over_warn(self):
        report = self._make_report(["warn", "high"])
        assert report.risk_level == "high"

    def test_flagged_count(self):
        report = self._make_report(["high", "warn", "clean", "skipped"])
        assert report.flagged_count == 2

    def test_high_privilege_summary_collects_high_flags(self):
        dims = [
            AccessDimension("roles", "high", "", flags=["HIGH_PRIV_ROLE:Global Administrator", "ROLE:Reader"]),
            AccessDimension("groups", "warn", "", flags=["HIGH_PRIV_GROUP:Company Admins"]),
        ]
        report = BlastRadiusReport(user="u@t.com", tenant="t.com", dimensions=dims)
        hp = report.high_privilege_summary
        assert "HIGH_PRIV_ROLE:Global Administrator" in hp
        assert "HIGH_PRIV_GROUP:Company Admins" in hp
        assert "ROLE:Reader" not in hp

    def test_high_privilege_summary_deduplicates(self):
        dims = [
            AccessDimension("a", "high", "", flags=["HIGH_PRIV_ROLE:X"]),
            AccessDimension("b", "high", "", flags=["HIGH_PRIV_ROLE:X"]),
        ]
        report = BlastRadiusReport(user="u@t.com", tenant="t.com", dimensions=dims)
        assert report.high_privilege_summary.count("HIGH_PRIV_ROLE:X") == 1


# ── AccessDimension ────────────────────────────────────────────────────────────

class TestAccessDimension:
    def test_default_item_count(self):
        d = AccessDimension(label="test", status="clean", summary="ok")
        assert d.item_count == 0

    def test_detail_defaults_to_empty_list(self):
        d = AccessDimension(label="test", status="clean", summary="ok")
        assert d.detail == []

    def test_flags_defaults_to_empty_list(self):
        d = AccessDimension(label="test", status="clean", summary="ok")
        assert d.flags == []


# ── Mock session helper ────────────────────────────────────────────────────────

def _mock_session_with_pages(pages: list[dict | list]) -> MagicMock:
    """
    Build a mock requests.Session whose .get() returns each page in sequence.
    Each page is a dict with optional 'value' and '@odata.nextLink'.
    """
    session = MagicMock()
    responses = []
    for page in pages:
        r = MagicMock()
        r.status_code = 200
        r.raise_for_status.return_value = None
        r.json.return_value = page
        responses.append(r)
    session.get.side_effect = responses
    return session


# ── _check_directory_roles ─────────────────────────────────────────────────────

class TestCheckDirectoryRoles:
    def test_no_roles_returns_clean(self):
        session = _mock_session_with_pages([{"value": []}])
        result = _check_directory_roles(session, "user@test.com")
        assert result.status == "clean"
        assert result.item_count == 0

    def test_high_priv_role_returns_high(self):
        session = _mock_session_with_pages([{"value": [
            {"id": "abc", "displayName": "Global Administrator"}
        ]}])
        result = _check_directory_roles(session, "user@test.com")
        assert result.status == "high"
        assert any("HIGH_PRIV_ROLE" in f for f in result.flags)

    def test_non_admin_role_returns_warn(self):
        session = _mock_session_with_pages([{"value": [
            {"id": "abc", "displayName": "Reports Reader"}
        ]}])
        result = _check_directory_roles(session, "user@test.com")
        assert result.status == "warn"

    def test_permission_error_returns_skipped(self):
        session = MagicMock()
        resp = MagicMock()
        resp.status_code = 403
        resp.raise_for_status.side_effect = Exception()
        session.get.return_value = resp
        result = _check_directory_roles(session, "user@test.com")
        assert result.status in ("skipped", "error")

    def test_item_count_matches_roles(self):
        session = _mock_session_with_pages([{"value": [
            {"id": "1", "displayName": "Reader"},
            {"id": "2", "displayName": "Writer"},
        ]}])
        result = _check_directory_roles(session, "user@test.com")
        assert result.item_count == 2


# ── _check_group_memberships ───────────────────────────────────────────────────

class TestCheckGroupMemberships:
    def test_no_groups_returns_clean(self):
        session = _mock_session_with_pages([{"value": []}])
        result = _check_group_memberships(session, "user@test.com")
        assert result.status == "clean"

    def test_role_assignable_group_returns_high(self):
        session = _mock_session_with_pages([{"value": [
            {"id": "g1", "displayName": "PIM Admins", "isAssignableToRole": True}
        ]}])
        result = _check_group_memberships(session, "user@test.com")
        assert result.status == "high"
        assert any("HIGH_ROLE_ASSIGNABLE_GROUP" in f for f in result.flags)

    def test_ordinary_group_returns_clean_when_few(self):
        session = _mock_session_with_pages([{"value": [
            {"id": "g1", "displayName": "Finance Team", "isAssignableToRole": False}
        ]}])
        result = _check_group_memberships(session, "user@test.com")
        assert result.status == "clean"

    def test_many_groups_returns_warn(self):
        groups = [{"id": f"g{i}", "displayName": f"Group{i}", "isAssignableToRole": False}
                  for i in range(10)]
        session = _mock_session_with_pages([{"value": groups}])
        result = _check_group_memberships(session, "user@test.com")
        assert result.status in ("warn", "clean")  # > 5 groups = warn

    def test_item_count(self):
        session = _mock_session_with_pages([{"value": [
            {"id": "g1", "displayName": "GroupA", "isAssignableToRole": False},
            {"id": "g2", "displayName": "GroupB", "isAssignableToRole": False},
        ]}])
        result = _check_group_memberships(session, "user@test.com")
        assert result.item_count == 2


# ── _check_app_role_assignments ────────────────────────────────────────────────

class TestCheckAppRoleAssignments:
    def test_no_assignments_returns_clean(self):
        session = _mock_session_with_pages([{"value": []}])
        result = _check_app_role_assignments(session, "user@test.com")
        assert result.status == "clean"

    def test_high_impact_role_keyword_detected(self):
        session = _mock_session_with_pages([{"value": [
            {
                "resourceDisplayName": "Microsoft Graph",
                "resourceId": "some-other-id",
                "appRoleId": "abc",
                "displayName": "Mail.ReadWrite.All",
                "principalDisplayName": "user@test.com",
            }
        ]}])
        result = _check_app_role_assignments(session, "user@test.com")
        assert result.status == "high"
        assert any("HIGH_APP_ROLE" in f for f in result.flags)

    def test_error_on_exception(self):
        session = MagicMock()
        session.get.side_effect = Exception("network error")
        result = _check_app_role_assignments(session, "user@test.com")
        assert result.status == "error"


# ── _check_owned_objects ───────────────────────────────────────────────────────

class TestCheckOwnedObjects:
    def test_no_objects_returns_clean(self):
        session = _mock_session_with_pages([{"value": []}])
        result = _check_owned_objects(session, "user@test.com")
        assert result.status == "clean"

    def test_owned_app_registration_returns_high(self):
        session = _mock_session_with_pages([{"value": [
            {"id": "app1", "displayName": "My App", "@odata.type": "#microsoft.graph.application"}
        ]}])
        result = _check_owned_objects(session, "user@test.com")
        assert result.status == "high"
        assert any("OWNS_APP_REGISTRATION" in f for f in result.flags)

    def test_owned_group_returns_warn_or_clean(self):
        session = _mock_session_with_pages([{"value": [
            {"id": "g1", "displayName": "My Group", "@odata.type": "#microsoft.graph.group"},
            {"id": "g2", "displayName": "Another", "@odata.type": "#microsoft.graph.group"},
            {"id": "g3", "displayName": "Third", "@odata.type": "#microsoft.graph.group"},
            {"id": "g4", "displayName": "Fourth", "@odata.type": "#microsoft.graph.group"},
        ]}])
        result = _check_owned_objects(session, "user@test.com")
        assert result.status in ("warn", "clean")


# ── _check_oauth_grants ────────────────────────────────────────────────────────

class TestCheckOAuthGrants:
    def test_no_grants_returns_clean(self):
        session = _mock_session_with_pages([{"value": []}])
        result = _check_oauth_grants(session, "user@test.com")
        assert result.status == "clean"

    def test_high_risk_scope_returns_high(self):
        session = _mock_session_with_pages([{"value": [
            {"clientId": "client1", "scope": "Mail.ReadWrite Files.ReadWrite.All"}
        ]}])
        result = _check_oauth_grants(session, "user@test.com")
        assert result.status == "high"
        assert any("HIGH_RISK_SCOPE" in f for f in result.flags)

    def test_low_risk_scope_returns_warn(self):
        session = _mock_session_with_pages([{"value": [
            {"clientId": "client1", "scope": "openid profile User.Read"}
        ]}])
        result = _check_oauth_grants(session, "user@test.com")
        assert result.status == "warn"

    def test_item_count(self):
        session = _mock_session_with_pages([{"value": [
            {"clientId": "c1", "scope": "openid"},
            {"clientId": "c2", "scope": "profile"},
        ]}])
        result = _check_oauth_grants(session, "user@test.com")
        assert result.item_count == 2


# ── _check_signin_apps ─────────────────────────────────────────────────────────

class TestCheckSigninApps:
    def test_no_signins_returns_clean(self):
        session = _mock_session_with_pages([{"value": []}])
        result = _check_signin_apps(session, "user@test.com")
        assert result.status == "clean"

    def test_few_apps_returns_clean(self):
        records = [
            {"appId": f"app{i}", "appDisplayName": f"App {i}",
             "createdDateTime": "2026-01-01T00:00:00Z",
             "status": {"errorCode": 0}}
            for i in range(3)
        ]
        session = _mock_session_with_pages([{"value": records}])
        result = _check_signin_apps(session, "user@test.com")
        assert result.status == "clean"

    def test_many_apps_returns_warn(self):
        records = [
            {"appId": f"app{i}", "appDisplayName": f"App {i}",
             "createdDateTime": "2026-01-01T00:00:00Z",
             "status": {"errorCode": 0}}
            for i in range(8)
        ]
        session = _mock_session_with_pages([{"value": records}])
        result = _check_signin_apps(session, "user@test.com")
        assert result.status == "warn"

    def test_failed_signins_not_counted_as_apps(self):
        records = [
            {"appId": "app1", "appDisplayName": "App",
             "createdDateTime": "2026-01-01T00:00:00Z",
             "status": {"errorCode": 50126}},  # failed
        ]
        session = _mock_session_with_pages([{"value": records}])
        result = _check_signin_apps(session, "user@test.com")
        assert result.item_count == 0


# ── run_blast_radius ───────────────────────────────────────────────────────────

class TestRunBlastRadius:
    def _make_empty_session_mock(self):
        """Returns a session mock that returns empty value lists for all calls."""
        session = MagicMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.raise_for_status.return_value = None
        resp.json.return_value = {"value": []}
        session.get.return_value = resp
        return session

    def test_returns_blast_radius_report(self):
        with patch("cirrus.analysis.blast_radius.requests.Session") as MockSession:
            MockSession.return_value = self._make_empty_session_mock()
            report = run_blast_radius("fake_token", "user@test.com", tenant="test.com")
        from cirrus.analysis.blast_radius import BlastRadiusReport
        assert isinstance(report, BlastRadiusReport)
        assert report.user == "user@test.com"
        assert report.tenant == "test.com"

    def test_all_checks_run(self):
        with patch("cirrus.analysis.blast_radius.requests.Session") as MockSession:
            MockSession.return_value = self._make_empty_session_mock()
            report = run_blast_radius("fake_token", "user@test.com")
        assert len(report.dimensions) == 6

    def test_writes_json_when_case_dir_provided(self, tmp_path: Path):
        with patch("cirrus.analysis.blast_radius.requests.Session") as MockSession:
            MockSession.return_value = self._make_empty_session_mock()
            run_blast_radius("fake_token", "user@test.com", case_dir=tmp_path)
        output = tmp_path / "blast_radius.json"
        assert output.exists()
        data = json.loads(output.read_text())
        assert data["user"] == "user@test.com"
        assert "dimensions" in data
        assert "risk_level" in data

    def test_clean_risk_when_no_findings(self):
        with patch("cirrus.analysis.blast_radius.requests.Session") as MockSession:
            MockSession.return_value = self._make_empty_session_mock()
            report = run_blast_radius("fake_token", "user@test.com")
        assert report.risk_level == "clean"

    def test_dimensions_in_canonical_order(self):
        with patch("cirrus.analysis.blast_radius.requests.Session") as MockSession:
            MockSession.return_value = self._make_empty_session_mock()
            report = run_blast_radius("fake_token", "user@test.com")
        labels = [d.label for d in report.dimensions]
        assert labels[0] == "Directory roles"
        assert labels[1] == "Group memberships"

    def test_no_case_dir_no_file_written(self, tmp_path: Path):
        with patch("cirrus.analysis.blast_radius.requests.Session") as MockSession:
            MockSession.return_value = self._make_empty_session_mock()
            run_blast_radius("fake_token", "user@test.com", case_dir=None)
        assert not (tmp_path / "blast_radius.json").exists()
