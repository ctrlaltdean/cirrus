"""
Unit tests for _run_inbox_analysis in triage.py.

Verifies that the "clean" verdict is only returned when zero inbox rules exist,
and that unflagged rules still yield "warn" so the analyst must review them.
"""

from __future__ import annotations

import pytest

from cirrus.analysis.triage import _run_inbox_analysis


def _rule(name="Test Rule", forward=None, permanent_delete=False,
          move_folder="", keywords=None):
    """Build a minimal inbox rule dict in Graph API shape."""
    actions: dict = {}
    if forward:
        actions["forwardTo"] = [{"emailAddress": {"address": forward}}]
    if permanent_delete:
        actions["permanentDelete"] = True
    if move_folder:
        actions["moveToFolder"] = move_folder
    conditions: dict = {}
    if keywords:
        conditions["subjectContains"] = keywords
    return {
        "displayName": name,
        "actions": actions,
        "conditions": conditions,
    }


# ── No rules ──────────────────────────────────────────────────────────────────

class TestNoRules:
    def test_clean_when_empty(self):
        cr, records = _run_inbox_analysis([])
        assert cr.status == "clean"
        assert records == []

    def test_summary_text(self):
        cr, _ = _run_inbox_analysis([])
        assert cr.label == "Inbox rules"
        assert "No inbox rules" in cr.summary


# ── Unflagged rules ───────────────────────────────────────────────────────────

class TestUnflaggedRules:
    """Rules that don't match any suspicious pattern → warn, not clean."""

    def test_plain_rule_is_warn(self):
        rules = [_rule("Newsletter Filter")]
        cr, records = _run_inbox_analysis(rules)
        assert cr.status == "warn"

    def test_plain_rule_returns_records(self):
        rules = [_rule("Newsletter Filter")]
        cr, records = _run_inbox_analysis(rules)
        assert len(records) == 1

    def test_summary_contains_manual_review_hint(self):
        rules = [_rule("My Rule")]
        cr, _ = _run_inbox_analysis(rules)
        assert "review manually" in cr.summary

    def test_multiple_unflagged_rules_all_returned(self):
        rules = [_rule("Rule A"), _rule("Rule B"), _rule("Rule C")]
        cr, records = _run_inbox_analysis(rules)
        assert cr.status == "warn"
        assert len(records) == 3

    def test_no_ioc_flags_when_unflagged(self):
        rules = [_rule("Plain Rule")]
        cr, _ = _run_inbox_analysis(rules)
        assert cr.flags == []


# ── Flagged rules ─────────────────────────────────────────────────────────────

class TestFlaggedRules:
    def test_forwarding_rule_is_warn_or_high(self):
        rules = [_rule(forward="attacker@evil.com")]
        cr, records = _run_inbox_analysis(rules)
        assert cr.status in ("warn", "high")
        assert any(f.startswith("FORWARDS_TO:") for f in cr.flags)

    def test_permanent_delete_flagged(self):
        rules = [_rule(permanent_delete=True)]
        cr, _ = _run_inbox_analysis(rules)
        assert "PERMANENT_DELETE" in cr.flags

    def test_move_to_deleted_flagged(self):
        rules = [_rule(move_folder="DeletedItems")]
        cr, _ = _run_inbox_analysis(rules)
        assert any(f.startswith("MOVES_TO_HIDDEN_FOLDER:") for f in cr.flags)

    def test_finance_keyword_flagged(self):
        rules = [_rule(keywords=["invoice"])]
        cr, _ = _run_inbox_analysis(rules)
        assert any(f.startswith("SUSPICIOUS_KEYWORD:") for f in cr.flags)

    def test_all_rules_returned_when_any_flagged(self):
        """When one rule is suspicious, ALL rules come back for manual review."""
        rules = [_rule("Safe Rule"), _rule(forward="attacker@evil.com")]
        cr, records = _run_inbox_analysis(rules)
        assert len(records) == 2

    def test_blank_rule_name_flagged(self):
        rules = [_rule(name="x")]
        cr, _ = _run_inbox_analysis(rules)
        assert any(f.startswith("SUSPICIOUS_RULE_NAME:") for f in cr.flags)


# ── Mixed: flagged + unflagged ────────────────────────────────────────────────

class TestMixedRules:
    def test_flagged_status_wins_over_unflagged(self):
        rules = [_rule("Safe Rule"), _rule(forward="x@evil.com")]
        cr, records = _run_inbox_analysis(rules)
        assert cr.status in ("warn", "high")
        assert len(records) == 2
