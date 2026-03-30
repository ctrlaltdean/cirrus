"""
Tests for AuditLogger chain integrity and the Case management class.

These verify the chain-of-custody guarantee — each entry's hash must
chain from the previous, and any tampering must be detectable.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cirrus.audit.logger import AuditLogger
from cirrus.output.case import Case


# ═══════════════════════════════════════════════════════════════════════════════
# AuditLogger
# ═══════════════════════════════════════════════════════════════════════════════

class TestAuditLoggerFiles:
    def test_creates_jsonl_and_txt_on_init(self, tmp_path: Path):
        AuditLogger(tmp_path)
        assert (tmp_path / "case_audit.jsonl").exists()
        assert (tmp_path / "case_audit.txt").exists()

    def test_session_open_written_on_init(self, tmp_path: Path):
        AuditLogger(tmp_path)
        lines = (tmp_path / "case_audit.jsonl").read_text().splitlines()
        first = json.loads(lines[0])
        assert first["action"] == "SESSION_OPEN"

    def test_session_close_written_on_close(self, tmp_path: Path):
        log = AuditLogger(tmp_path)
        log.close()
        lines = (tmp_path / "case_audit.jsonl").read_text().splitlines()
        last = json.loads(lines[-1])
        assert last["action"] == "SESSION_CLOSE"

    def test_entries_are_appended_not_overwritten(self, tmp_path: Path):
        log = AuditLogger(tmp_path)
        log.log_event("TEST_EVENT_1")
        log.log_event("TEST_EVENT_2")
        lines = (tmp_path / "case_audit.jsonl").read_text().splitlines()
        actions = [json.loads(l)["action"] for l in lines]
        assert "TEST_EVENT_1" in actions
        assert "TEST_EVENT_2" in actions


class TestAuditLoggerEntryContent:
    def test_each_entry_has_required_fields(self, tmp_path: Path):
        log = AuditLogger(tmp_path)
        log.log_event("TEST_EVENT", {"key": "value"})
        lines = (tmp_path / "case_audit.jsonl").read_text().splitlines()
        for line in lines:
            entry = json.loads(line)
            assert "timestamp" in entry
            assert "action" in entry
            assert "prev_hash" in entry
            assert "entry_hash" in entry
            assert "analyst" in entry
            assert "hostname" in entry

    def test_log_event_details_preserved(self, tmp_path: Path):
        log = AuditLogger(tmp_path)
        log.log_event("CUSTOM_EVENT", {"foo": "bar", "count": 42})
        lines = (tmp_path / "case_audit.jsonl").read_text().splitlines()
        events = [json.loads(l) for l in lines if json.loads(l)["action"] == "CUSTOM_EVENT"]
        assert events
        assert events[0]["details"]["foo"] == "bar"

    def test_log_collection_complete_includes_record_count(self, tmp_path: Path):
        log = AuditLogger(tmp_path)
        fake_file = tmp_path / "dummy.json"
        fake_file.write_text("[]")
        log.log_collection_complete("signin_logs", 150, fake_file, "abc123")
        lines = (tmp_path / "case_audit.jsonl").read_text().splitlines()
        entries = [json.loads(l) for l in lines if json.loads(l)["action"] == "COLLECTION_COMPLETE"]
        assert entries
        assert entries[0]["record_count"] == 150
        assert entries[0]["file_hash"] == "abc123"

    def test_first_entry_prev_hash_is_zeros(self, tmp_path: Path):
        AuditLogger(tmp_path)
        lines = (tmp_path / "case_audit.jsonl").read_text().splitlines()
        first = json.loads(lines[0])
        assert first["prev_hash"] == "0" * 64

    def test_second_entry_prev_hash_matches_first_entry_hash(self, tmp_path: Path):
        log = AuditLogger(tmp_path)
        log.log_event("SECOND")
        lines = (tmp_path / "case_audit.jsonl").read_text().splitlines()
        first = json.loads(lines[0])
        second = json.loads(lines[1])
        assert second["prev_hash"] == first["entry_hash"]


# ═══════════════════════════════════════════════════════════════════════════════
# AuditLogger.verify_chain
# ═══════════════════════════════════════════════════════════════════════════════

class TestAuditChainIntegrity:
    def test_clean_chain_verifies(self, tmp_path: Path):
        log = AuditLogger(tmp_path)
        log.log_event("EVENT_A")
        log.log_event("EVENT_B")
        log.close()
        is_valid, errors = log.verify_chain()
        assert is_valid
        assert errors == []

    def test_empty_log_verifies(self, tmp_path: Path):
        """Empty log (no file) should be considered valid."""
        log = AuditLogger(tmp_path)
        # Manually delete the log to simulate empty state
        jsonl = tmp_path / "case_audit.jsonl"
        jsonl.unlink()
        is_valid, errors = log.verify_chain()
        assert is_valid

    def test_tampered_entry_detected(self, tmp_path: Path):
        log = AuditLogger(tmp_path)
        log.log_event("LEGITIMATE_EVENT", {"data": "original"})
        log.close()

        # Tamper with the middle entry: change the details
        jsonl_path = tmp_path / "case_audit.jsonl"
        lines = jsonl_path.read_text().splitlines()
        for i, line in enumerate(lines):
            entry = json.loads(line)
            if entry.get("action") == "LEGITIMATE_EVENT":
                entry["details"]["data"] = "TAMPERED"
                lines[i] = json.dumps(entry)
                break
        jsonl_path.write_text("\n".join(lines) + "\n")

        is_valid, errors = log.verify_chain()
        assert not is_valid
        assert any("mismatch" in e.lower() or "tamper" in e.lower() for e in errors)

    def test_deleted_entry_breaks_chain(self, tmp_path: Path):
        log = AuditLogger(tmp_path)
        log.log_event("EVENT_A")
        log.log_event("EVENT_B")
        log.close()

        # Delete the middle entry
        jsonl_path = tmp_path / "case_audit.jsonl"
        lines = jsonl_path.read_text().splitlines()
        # Remove EVENT_A (index 1) — this will break EVENT_B's prev_hash link
        filtered = [l for l in lines if json.loads(l).get("action") != "EVENT_A"]
        jsonl_path.write_text("\n".join(filtered) + "\n")

        is_valid, errors = log.verify_chain()
        assert not is_valid

    def test_multiple_events_chain_is_valid(self, tmp_path: Path):
        log = AuditLogger(tmp_path)
        for i in range(10):
            log.log_event(f"EVENT_{i}", {"i": i})
        log.close()
        is_valid, errors = log.verify_chain()
        assert is_valid, f"Chain failed with errors: {errors}"


# ═══════════════════════════════════════════════════════════════════════════════
# Case
# ═══════════════════════════════════════════════════════════════════════════════

class TestCase:
    def test_create_makes_directory(self, tmp_path: Path):
        case = Case.create("contoso.com", tmp_path)
        assert case.case_dir.exists()
        assert case.case_dir.is_dir()

    def test_create_folder_name_includes_tenant_slug(self, tmp_path: Path):
        case = Case.create("contoso.com", tmp_path)
        assert "CONTOSO" in case.case_dir.name.upper()

    def test_create_with_case_name(self, tmp_path: Path):
        case = Case.create("contoso.com", tmp_path, case_name="INC-2026-001")
        assert "INC" in case.case_dir.name or "2026" in case.case_dir.name

    def test_creates_audit_log_on_init(self, tmp_path: Path):
        case = Case.create("contoso.com", tmp_path)
        assert (case.case_dir / "case_audit.jsonl").exists()

    def test_close_writes_session_close(self, tmp_path: Path):
        case = Case.create("contoso.com", tmp_path)
        case.close()
        lines = (case.case_dir / "case_audit.jsonl").read_text().splitlines()
        actions = [json.loads(l)["action"] for l in lines]
        assert "SESSION_CLOSE" in actions

    def test_verify_integrity_clean(self, tmp_path: Path):
        case = Case.create("contoso.com", tmp_path)
        case.audit.log_event("WORKFLOW_START", {"workflow": "ato"})
        case.close()
        is_valid, errors = case.verify_integrity()
        assert is_valid
        assert errors == []

    def test_open_existing_case(self, tmp_path: Path):
        case1 = Case.create("contoso.com", tmp_path)
        case_dir = case1.case_dir

        case2 = Case.open_existing(case_dir)
        assert case2.case_dir == case_dir

    def test_open_nonexistent_case_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            Case.open_existing(tmp_path / "does_not_exist")

    def test_artifact_path_returns_correct_path(self, tmp_path: Path):
        case = Case.create("contoso.com", tmp_path)
        path = case.artifact_path("signin_logs.json")
        assert path == case.case_dir / "signin_logs.json"

    def test_two_cases_have_unique_directories(self, tmp_path: Path):
        import time
        case1 = Case.create("contoso.com", tmp_path)
        time.sleep(1)  # ensure different timestamp
        case2 = Case.create("contoso.com", tmp_path)
        assert case1.case_dir != case2.case_dir
