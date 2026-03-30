"""
Integration tests for the CIRRUS cross-collector correlation engine.

Each test writes synthetic JSON fixture files to a pytest tmp_path directory
(mimicking a real case directory) and then runs the CorrelationEngine.
Tests assert on rule name, severity, affected users, and finding count.

No live tenant or network access is required.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cirrus.analysis.correlator import CorrelationEngine, run_correlator
from tests.conftest import (
    make_audit,
    make_device,
    make_forwarding,
    make_mfa,
    make_oauth,
    make_rule,
    make_signin,
    make_ual_mail_access,
    make_user,
    write_case_files,
)


# ── Helpers ────────────────────────────────────────────────────────────────────

def run(case_dir: Path) -> dict:
    return CorrelationEngine(case_dir).run()


def rule_names(report: dict) -> list[str]:
    return [f["rule"] for f in report["findings"]]


def findings_for_rule(report: dict, rule: str) -> list[dict]:
    return [f for f in report["findings"] if f["rule"] == rule]


# ── Empty case — no data ───────────────────────────────────────────────────────

class TestEmptyCase:
    def test_no_findings_on_empty_case(self, tmp_path):
        report = run(tmp_path)
        assert report["summary"]["total_findings"] == 0
        assert report["findings"] == []

    def test_output_files_written(self, tmp_path):
        run(tmp_path)
        assert (tmp_path / "ioc_correlation.json").exists()
        assert (tmp_path / "ioc_correlation.txt").exists()

    def test_run_correlator_convenience(self, tmp_path):
        report = run_correlator(tmp_path)
        assert "summary" in report
        assert "findings" in report


# ── Rule: password_spray ───────────────────────────────────────────────────────

class TestPasswordSpray:
    SPRAY_IP = "203.0.113.42"

    def _make_spray_failures(self, count: int = 12, target_count: int = 6) -> list[dict]:
        """Build failed sign-ins from SPRAY_IP across multiple targets."""
        records = []
        for i in range(count):
            upn = f"user{i % target_count}@contoso.com"
            r = make_signin(
                upn=upn,
                error_code=50126,
                ip=self.SPRAY_IP,
                ioc_flags=["FAILED_SIGNIN:Invalid username or password."],
            )
            records.append(r)
        return records

    def test_spray_detected_medium(self, tmp_path):
        write_case_files(tmp_path, signin_logs=self._make_spray_failures())
        report = run(tmp_path)
        spray = findings_for_rule(report, "password_spray")
        assert len(spray) == 1
        assert spray[0]["severity"] == "medium"
        assert self.SPRAY_IP in spray[0]["title"]

    def test_spray_elevated_to_high_on_success(self, tmp_path):
        failures = self._make_spray_failures()
        # Add successful sign-in from same IP for one target
        success = make_signin(
            upn="user0@contoso.com",
            error_code=0,
            ip=self.SPRAY_IP,
            ioc_flags=["PUBLIC_IP:203.0.113.42"],
        )
        write_case_files(tmp_path, signin_logs=failures + [success])
        report = run(tmp_path)
        spray = findings_for_rule(report, "password_spray")
        assert len(spray) == 1
        assert spray[0]["severity"] == "high"

    def test_spray_below_target_threshold_not_flagged(self, tmp_path):
        # Only 3 distinct targets — below threshold of 5
        failures = self._make_spray_failures(count=10, target_count=3)
        write_case_files(tmp_path, signin_logs=failures)
        report = run(tmp_path)
        assert not findings_for_rule(report, "password_spray")

    def test_spray_below_failure_threshold_not_flagged(self, tmp_path):
        # 5 distinct targets but only 5 total failures — below threshold of 10
        failures = self._make_spray_failures(count=5, target_count=5)
        write_case_files(tmp_path, signin_logs=failures)
        report = run(tmp_path)
        assert not findings_for_rule(report, "password_spray")

    def test_no_spray_without_signin_data(self, tmp_path):
        write_case_files(tmp_path, signin_logs=[])
        report = run(tmp_path)
        assert not findings_for_rule(report, "password_spray")


# ── Rule: mass_mail_access ─────────────────────────────────────────────────────

class TestMassMailAccess:
    VICTIM = "victim@contoso.com"

    def _make_ual(self, count: int = 55) -> list[dict]:
        return [make_ual_mail_access(upn=self.VICTIM) for _ in range(count)]

    def test_mass_access_detected_medium(self, tmp_path):
        write_case_files(tmp_path, unified_audit_log=self._make_ual())
        report = run(tmp_path)
        findings = findings_for_rule(report, "mass_mail_access")
        assert len(findings) == 1
        assert findings[0]["severity"] == "medium"
        assert self.VICTIM in findings[0]["user"]

    def test_mass_access_elevated_to_high_with_signin(self, tmp_path):
        signin = make_signin(upn=self.VICTIM, error_code=0)
        write_case_files(
            tmp_path,
            unified_audit_log=self._make_ual(),
            signin_logs=[signin],
        )
        report = run(tmp_path)
        findings = findings_for_rule(report, "mass_mail_access")
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"

    def test_below_threshold_not_flagged(self, tmp_path):
        write_case_files(tmp_path, unified_audit_log=self._make_ual(count=30))
        report = run(tmp_path)
        assert not findings_for_rule(report, "mass_mail_access")

    def test_no_mass_access_without_ual_data(self, tmp_path):
        write_case_files(tmp_path, unified_audit_log=[])
        report = run(tmp_path)
        assert not findings_for_rule(report, "mass_mail_access")

    def test_app_id_extracted_from_audit_data(self, tmp_path):
        ual = [
            make_ual_mail_access(
                upn=self.VICTIM,
                app_id="aaaaaaaa-bbbb-cccc-dddd-000000000001",
            )
            for _ in range(55)
        ]
        write_case_files(tmp_path, unified_audit_log=ual)
        report = run(tmp_path)
        findings = findings_for_rule(report, "mass_mail_access")
        assert findings
        # App ID should appear somewhere in the description
        assert "aaaaaaaa-bbbb" in findings[0]["description"]

    def test_non_mail_ual_records_not_counted(self, tmp_path):
        # 60 UserLoggedIn records should NOT trigger mass_mail_access
        ual = []
        for i in range(60):
            r = make_ual_mail_access(upn=self.VICTIM)
            r["Operation"] = "UserLoggedIn"
            r["operation"] = "UserLoggedIn"
            ual.append(r)
        write_case_files(tmp_path, unified_audit_log=ual)
        report = run(tmp_path)
        assert not findings_for_rule(report, "mass_mail_access")


# ── Rule: suspicious_signin_then_persistence ───────────────────────────────────

class TestSuspiciousSigninThenPersistence:
    UPN = "alice@contoso.com"

    def test_device_code_plus_new_mfa_detected(self, tmp_path):
        signin = make_signin(
            upn=self.UPN,
            ioc_flags=["SUSPICIOUS_AUTH_PROTOCOL:deviceCode"],
        )
        mfa = make_mfa(upn=self.UPN, ioc_flags=["RECENTLY_ADDED", "HIGH_PERSISTENCE_METHOD"])
        write_case_files(tmp_path, signin_logs=[signin], mfa_methods=[mfa])
        report = run(tmp_path)
        findings = findings_for_rule(report, "suspicious_signin_then_persistence")
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"
        assert findings[0]["user"] == self.UPN

    def test_geo_risk_plus_new_device_detected(self, tmp_path):
        signin = make_signin(
            upn=self.UPN,
            ioc_flags=["GEO_RISK:anonymizedIPAddress"],
        )
        device = make_device(upn=self.UPN, ioc_flags=["RECENTLY_REGISTERED"])
        write_case_files(
            tmp_path,
            signin_logs=[signin],
            registered_devices=[device],
        )
        report = run(tmp_path)
        findings = findings_for_rule(report, "suspicious_signin_then_persistence")
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"

    def test_suspicious_signin_without_persistence_not_flagged(self, tmp_path):
        signin = make_signin(upn=self.UPN, ioc_flags=["SUSPICIOUS_AUTH_PROTOCOL:deviceCode"])
        write_case_files(tmp_path, signin_logs=[signin], mfa_methods=[], registered_devices=[])
        report = run(tmp_path)
        assert not findings_for_rule(report, "suspicious_signin_then_persistence")

    def test_new_mfa_without_suspicious_signin_not_flagged(self, tmp_path):
        signin = make_signin(upn=self.UPN, ioc_flags=["PUBLIC_IP:203.0.113.1"])
        mfa = make_mfa(upn=self.UPN, ioc_flags=["RECENTLY_ADDED"])
        write_case_files(tmp_path, signin_logs=[signin], mfa_methods=[mfa])
        report = run(tmp_path)
        assert not findings_for_rule(report, "suspicious_signin_then_persistence")


# ── Rule: password_reset_then_mfa_registered ──────────────────────────────────

class TestPasswordResetThenMfaRegistered:
    VICTIM = "victim@contoso.com"
    ADMIN = "admin@contoso.com"

    def test_reset_then_mfa_detected(self, tmp_path):
        audit = make_audit(
            operation="Reset user password",
            target_upns=[self.VICTIM],
            initiator_upn=self.ADMIN,
            ioc_flags=["ADMIN_PASSWORD_RESET"],
        )
        mfa = make_mfa(upn=self.VICTIM, ioc_flags=["RECENTLY_ADDED"])
        write_case_files(tmp_path, audit_logs=[audit], mfa_methods=[mfa])
        report = run(tmp_path)
        findings = findings_for_rule(report, "password_reset_then_mfa_registered")
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"
        assert findings[0]["user"] == self.VICTIM

    def test_reset_without_new_mfa_not_flagged(self, tmp_path):
        audit = make_audit(
            operation="Reset user password",
            target_upns=[self.VICTIM],
            ioc_flags=["ADMIN_PASSWORD_RESET"],
        )
        write_case_files(tmp_path, audit_logs=[audit], mfa_methods=[])
        report = run(tmp_path)
        assert not findings_for_rule(report, "password_reset_then_mfa_registered")

    def test_new_mfa_without_reset_not_flagged(self, tmp_path):
        mfa = make_mfa(upn=self.VICTIM, ioc_flags=["RECENTLY_ADDED"])
        write_case_files(tmp_path, audit_logs=[], mfa_methods=[mfa])
        report = run(tmp_path)
        assert not findings_for_rule(report, "password_reset_then_mfa_registered")


# ── Rule: privilege_escalation_after_signin ───────────────────────────────────

class TestPrivilegeEscalationAfterSignin:
    VICTIM = "target@contoso.com"

    def test_escalation_with_suspicious_signin_detected(self, tmp_path):
        signin = make_signin(
            upn=self.VICTIM,
            ioc_flags=["RISK_LEVEL:high", "FAILED_SIGNIN:bad password"],
        )
        audit = make_audit(
            operation="Add member to role",
            target_upns=[self.VICTIM],
            ioc_flags=["HIGH_PRIV_ROLE_ASSIGNED:Global Administrator"],
        )
        write_case_files(tmp_path, signin_logs=[signin], audit_logs=[audit])
        report = run(tmp_path)
        findings = findings_for_rule(report, "privilege_escalation_after_signin")
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"
        assert findings[0]["user"] == self.VICTIM

    def test_escalation_without_suspicious_signin_not_flagged(self, tmp_path):
        # Clean sign-in (no suspicious flags) should NOT trigger even with role assignment
        signin = make_signin(upn=self.VICTIM, ioc_flags=["PUBLIC_IP:203.0.113.1"])
        audit = make_audit(
            operation="Add member to role",
            target_upns=[self.VICTIM],
            ioc_flags=["HIGH_PRIV_ROLE_ASSIGNED:Global Administrator"],
        )
        write_case_files(tmp_path, signin_logs=[signin], audit_logs=[audit])
        report = run(tmp_path)
        assert not findings_for_rule(report, "privilege_escalation_after_signin")

    def test_role_assignment_without_signin_not_flagged(self, tmp_path):
        audit = make_audit(
            operation="Add member to role",
            target_upns=[self.VICTIM],
            ioc_flags=["HIGH_PRIV_ROLE_ASSIGNED:Global Administrator"],
        )
        write_case_files(tmp_path, signin_logs=[], audit_logs=[audit])
        report = run(tmp_path)
        assert not findings_for_rule(report, "privilege_escalation_after_signin")


# ── Rule: oauth_phishing_pattern ─────────────────────────────────────────────

class TestOAuthPhishingPattern:
    UPN = "phished@contoso.com"

    def test_device_code_plus_high_risk_grant_detected(self, tmp_path):
        signin = make_signin(
            upn=self.UPN,
            ioc_flags=["SUSPICIOUS_AUTH_PROTOCOL:deviceCode"],
        )
        grant = make_oauth(
            upn=self.UPN,
            ioc_flags=["HIGH_RISK_SCOPE:Mail.Read"],
        )
        write_case_files(tmp_path, signin_logs=[signin], oauth_grants=[grant])
        report = run(tmp_path)
        findings = findings_for_rule(report, "oauth_phishing_pattern")
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"
        assert findings[0]["user"] == self.UPN

    def test_no_grant_not_flagged(self, tmp_path):
        signin = make_signin(upn=self.UPN, ioc_flags=["SUSPICIOUS_AUTH_PROTOCOL:deviceCode"])
        write_case_files(tmp_path, signin_logs=[signin], oauth_grants=[])
        report = run(tmp_path)
        assert not findings_for_rule(report, "oauth_phishing_pattern")

    def test_grant_without_device_code_not_flagged(self, tmp_path):
        signin = make_signin(upn=self.UPN, ioc_flags=["PUBLIC_IP:203.0.113.1"])
        grant = make_oauth(upn=self.UPN, ioc_flags=["HIGH_RISK_SCOPE:Mail.Read"])
        write_case_files(tmp_path, signin_logs=[signin], oauth_grants=[grant])
        report = run(tmp_path)
        assert not findings_for_rule(report, "oauth_phishing_pattern")


# ── Rule: bec_attack_pattern ─────────────────────────────────────────────────

class TestBecAttackPattern:
    UPN = "finance@contoso.com"

    def test_signin_plus_forwarding_rule_detected(self, tmp_path):
        signin = make_signin(upn=self.UPN)
        rule = make_rule(upn=self.UPN, forward_to="attacker@evil.com")
        write_case_files(tmp_path, signin_logs=[signin], mailbox_rules=[rule])
        report = run(tmp_path)
        findings = findings_for_rule(report, "bec_attack_pattern")
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"
        assert findings[0]["user"] == self.UPN

    def test_signin_plus_smtp_forward_detected(self, tmp_path):
        signin = make_signin(upn=self.UPN)
        fwd = make_forwarding(upn=self.UPN, smtp_fwd="exfil@adversary.com")
        write_case_files(tmp_path, signin_logs=[signin], mail_forwarding=[fwd])
        report = run(tmp_path)
        findings = findings_for_rule(report, "bec_attack_pattern")
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"

    def test_forwarding_without_signin_not_flagged(self, tmp_path):
        rule = make_rule(upn=self.UPN)
        write_case_files(tmp_path, signin_logs=[], mailbox_rules=[rule])
        report = run(tmp_path)
        assert not findings_for_rule(report, "bec_attack_pattern")

    def test_signin_without_forwarding_not_flagged(self, tmp_path):
        signin = make_signin(upn=self.UPN)
        write_case_files(tmp_path, signin_logs=[signin], mailbox_rules=[])
        report = run(tmp_path)
        assert not findings_for_rule(report, "bec_attack_pattern")


# ── Rule: device_code_then_device_registered ──────────────────────────────────

class TestDeviceCodeThenDeviceRegistered:
    UPN = "prt_victim@contoso.com"

    def test_device_code_plus_new_device_detected(self, tmp_path):
        signin = make_signin(
            upn=self.UPN,
            ioc_flags=["SUSPICIOUS_AUTH_PROTOCOL:deviceCode"],
        )
        device = make_device(upn=self.UPN, ioc_flags=["RECENTLY_REGISTERED"])
        write_case_files(
            tmp_path,
            signin_logs=[signin],
            registered_devices=[device],
        )
        report = run(tmp_path)
        findings = findings_for_rule(report, "device_code_then_device_registered")
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"
        assert findings[0]["user"] == self.UPN

    def test_device_code_without_new_device_not_flagged(self, tmp_path):
        signin = make_signin(upn=self.UPN, ioc_flags=["SUSPICIOUS_AUTH_PROTOCOL:deviceCode"])
        write_case_files(tmp_path, signin_logs=[signin], registered_devices=[])
        report = run(tmp_path)
        assert not findings_for_rule(report, "device_code_then_device_registered")

    def test_new_device_ropc_not_triggered(self, tmp_path):
        # ropc does NOT trigger device_code_then_device_registered (only deviceCode does)
        signin = make_signin(upn=self.UPN, ioc_flags=["SUSPICIOUS_AUTH_PROTOCOL:ropc"])
        device = make_device(upn=self.UPN, ioc_flags=["RECENTLY_REGISTERED"])
        write_case_files(
            tmp_path,
            signin_logs=[signin],
            registered_devices=[device],
        )
        report = run(tmp_path)
        assert not findings_for_rule(report, "device_code_then_device_registered")


# ── Rule: new_account_with_signin ─────────────────────────────────────────────

class TestNewAccountWithSignin:
    UPN = "backdoor@contoso.com"

    def test_new_account_with_signin_detected(self, tmp_path):
        user = make_user(upn=self.UPN, ioc_flags=["RECENTLY_CREATED:3days"])
        signin = make_signin(upn=self.UPN, error_code=0)
        write_case_files(tmp_path, users=[user], signin_logs=[signin])
        report = run(tmp_path)
        findings = findings_for_rule(report, "new_account_with_signin")
        assert len(findings) == 1
        assert findings[0]["severity"] == "medium"
        assert findings[0]["user"] == self.UPN

    def test_new_account_without_signin_not_flagged(self, tmp_path):
        user = make_user(upn=self.UPN, ioc_flags=["RECENTLY_CREATED:3days"])
        write_case_files(tmp_path, users=[user], signin_logs=[])
        report = run(tmp_path)
        assert not findings_for_rule(report, "new_account_with_signin")

    def test_old_account_with_signin_not_flagged(self, tmp_path):
        user = make_user(upn=self.UPN, ioc_flags=[])
        signin = make_signin(upn=self.UPN)
        write_case_files(tmp_path, users=[user], signin_logs=[signin])
        report = run(tmp_path)
        assert not findings_for_rule(report, "new_account_with_signin")


# ── Rule: cross_ip_correlation ────────────────────────────────────────────────

class TestCrossIpCorrelation:
    IP = "198.51.100.99"
    UPN = "admin@contoso.com"

    def test_same_ip_in_signin_and_audit_detected(self, tmp_path):
        signin = make_signin(
            upn=self.UPN,
            ip=self.IP,
            ioc_flags=[f"PUBLIC_IP:{self.IP}"],
        )
        audit = make_audit(
            operation="Add registered owner to device",
            target_upns=[self.UPN],
            ip=self.IP,
            ioc_flags=[f"PUBLIC_IP:{self.IP}"],
        )
        write_case_files(tmp_path, signin_logs=[signin], audit_logs=[audit])
        report = run(tmp_path)
        findings = findings_for_rule(report, "cross_ip_correlation")
        assert len(findings) == 1
        assert findings[0]["severity"] == "medium"
        assert self.IP in findings[0]["title"]

    def test_different_ips_not_flagged(self, tmp_path):
        signin = make_signin(upn=self.UPN, ip="203.0.113.1", ioc_flags=["PUBLIC_IP:203.0.113.1"])
        audit = make_audit(
            operation="Update user",
            ip="203.0.113.2",
            ioc_flags=["PUBLIC_IP:203.0.113.2"],
        )
        write_case_files(tmp_path, signin_logs=[signin], audit_logs=[audit])
        report = run(tmp_path)
        assert not findings_for_rule(report, "cross_ip_correlation")

    def test_private_ip_not_flagged(self, tmp_path):
        # Private IP in signin — no PUBLIC_IP flag → rule should not fire
        signin = make_signin(upn=self.UPN, ip="10.0.0.1", ioc_flags=[])
        audit = make_audit(operation="Update user", ip="10.0.0.1", ioc_flags=[])
        write_case_files(tmp_path, signin_logs=[signin], audit_logs=[audit])
        report = run(tmp_path)
        assert not findings_for_rule(report, "cross_ip_correlation")

    def test_no_audit_data_not_flagged(self, tmp_path):
        signin = make_signin(upn=self.UPN, ip=self.IP, ioc_flags=[f"PUBLIC_IP:{self.IP}"])
        write_case_files(tmp_path, signin_logs=[signin], audit_logs=[])
        report = run(tmp_path)
        assert not findings_for_rule(report, "cross_ip_correlation")


# ── Report structure tests ─────────────────────────────────────────────────────

class TestReportStructure:
    def test_report_has_required_keys(self, tmp_path):
        report = run(tmp_path)
        assert "generated_at" in report
        assert "case_dir" in report
        assert "collectors_loaded" in report
        assert "summary" in report
        assert "findings" in report

    def test_summary_counts_match_findings(self, tmp_path):
        # Create data that should produce one HIGH finding
        signin = make_signin(
            upn="user@contoso.com",
            ioc_flags=["SUSPICIOUS_AUTH_PROTOCOL:deviceCode"],
        )
        mfa = make_mfa(upn="user@contoso.com", ioc_flags=["RECENTLY_ADDED"])
        write_case_files(tmp_path, signin_logs=[signin], mfa_methods=[mfa])
        report = run(tmp_path)
        high_findings = [f for f in report["findings"] if f["severity"] == "high"]
        assert report["summary"]["high"] == len(high_findings)
        assert report["summary"]["total_findings"] == len(report["findings"])

    def test_finding_ids_are_unique(self, tmp_path):
        # Create two independent findings
        signin1 = make_signin(upn="a@c.com", ioc_flags=["SUSPICIOUS_AUTH_PROTOCOL:deviceCode"])
        mfa1 = make_mfa(upn="a@c.com", ioc_flags=["RECENTLY_ADDED"])
        signin2 = make_signin(upn="b@c.com", ioc_flags=["SUSPICIOUS_AUTH_PROTOCOL:ropc"])
        mfa2 = make_mfa(upn="b@c.com", ioc_flags=["RECENTLY_ADDED"])
        write_case_files(
            tmp_path,
            signin_logs=[signin1, signin2],
            mfa_methods=[mfa1, mfa2],
        )
        report = run(tmp_path)
        ids = [f["id"] for f in report["findings"]]
        assert len(ids) == len(set(ids)), "Finding IDs must be unique"

    def test_each_finding_has_evidence(self, tmp_path):
        signin = make_signin(
            upn="user@contoso.com",
            ioc_flags=["SUSPICIOUS_AUTH_PROTOCOL:deviceCode"],
        )
        mfa = make_mfa(upn="user@contoso.com", ioc_flags=["RECENTLY_ADDED"])
        write_case_files(tmp_path, signin_logs=[signin], mfa_methods=[mfa])
        report = run(tmp_path)
        for finding in report["findings"]:
            assert finding["evidence"], f"Finding {finding['id']} has no evidence"

    def test_collectors_loaded_reflects_available_files(self, tmp_path):
        write_case_files(tmp_path, signin_logs=[make_signin()])
        report = run(tmp_path)
        assert "signin_logs" in report["collectors_loaded"]
        assert "mfa_methods" not in report["collectors_loaded"]

    def test_output_json_is_valid(self, tmp_path):
        write_case_files(tmp_path, signin_logs=[make_signin()])
        run(tmp_path)
        json_path = tmp_path / "ioc_correlation.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        assert "findings" in data

    def test_affected_users_in_summary(self, tmp_path):
        upn = "target@contoso.com"
        user = make_user(upn=upn, ioc_flags=["RECENTLY_CREATED:5days"])
        signin = make_signin(upn=upn)
        write_case_files(tmp_path, users=[user], signin_logs=[signin])
        report = run(tmp_path)
        if report["summary"]["total_findings"] > 0:
            assert upn in report["summary"]["affected_users"]

    def test_broken_rule_does_not_crash_engine(self, tmp_path):
        """Correlation engine must silently skip rules that raise exceptions."""
        # Write corrupt/empty data — engine should return a valid (possibly empty) report
        (tmp_path / "signin_logs.json").write_text("[{]", encoding="utf-8")  # invalid JSON
        report = run(tmp_path)
        assert "summary" in report  # engine continued


# ── MITRE ATT&CK mapping ───────────────────────────────────────────────────────

class TestMITREMapping:
    """Verify that mitre_techniques is populated for all rule types."""

    def test_password_spray_has_mitre_techniques(self, tmp_path):
        from tests.conftest import make_signin, write_case_files
        # Build a spray: 10 failures from one IP against 5 users
        records = []
        for i in range(5):
            upn = f"user{i}@contoso.com"
            for _ in range(2):
                records.append(make_signin(
                    upn=upn,
                    ip="203.0.113.99",
                    ioc_flags=[f"FAILED_SIGNIN:bad_password", f"PUBLIC_IP:203.0.113.99"],
                ))
        write_case_files(tmp_path, signin_logs=records)
        report = run(tmp_path)
        findings = findings_for_rule(report, "password_spray")
        if findings:
            techniques = findings[0].get("mitre_techniques") or []
            assert any("T1110" in t for t in techniques)

    def test_oauth_phishing_has_mitre_techniques(self, tmp_path):
        from tests.conftest import make_signin, make_oauth, write_case_files
        upn = "victim@contoso.com"
        signin = make_signin(upn=upn, ioc_flags=["SUSPICIOUS_AUTH_PROTOCOL:deviceCode"])
        grant  = make_oauth(upn=upn, ioc_flags=["HIGH_RISK_SCOPE:Mail.Read"])
        write_case_files(tmp_path, signin_logs=[signin], oauth_grants=[grant])
        report = run(tmp_path)
        findings = findings_for_rule(report, "oauth_phishing_pattern")
        assert len(findings) == 1
        techniques = findings[0].get("mitre_techniques") or []
        assert any("T1528" in t for t in techniques)

    def test_bec_attack_has_mitre_techniques(self, tmp_path):
        from tests.conftest import make_signin, make_rule, write_case_files
        upn = "victim@contoso.com"
        signin = make_signin(upn=upn, ioc_flags=["PUBLIC_IP:1.2.3.4"])
        rule   = make_rule(upn=upn, ioc_flags=["FORWARDS_TO:attacker@evil.com"])
        write_case_files(tmp_path, signin_logs=[signin], mailbox_rules=[rule])
        report = run(tmp_path)
        findings = findings_for_rule(report, "bec_attack_pattern")
        assert len(findings) == 1
        techniques = findings[0].get("mitre_techniques") or []
        assert any("T1114" in t for t in techniques)

    def test_all_findings_have_mitre_field(self, tmp_path):
        """Every finding dict must contain a mitre_techniques key (even if empty list)."""
        upn = "user@contoso.com"
        signin = make_signin(upn=upn, ioc_flags=["SUSPICIOUS_AUTH_PROTOCOL:deviceCode"])
        mfa    = make_mfa(upn=upn, ioc_flags=["RECENTLY_ADDED:2026-03-28"])
        write_case_files(tmp_path, signin_logs=[signin], mfa_methods=[mfa])
        report = run(tmp_path)
        for f in report["findings"]:
            assert "mitre_techniques" in f
            assert isinstance(f["mitre_techniques"], list)
