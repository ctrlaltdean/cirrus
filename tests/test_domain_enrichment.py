"""
Tests for cirrus/analysis/domain_enrichment.py

Covers:
  - _extract_domains_from_case() — scans IOC flags from JSON files
  - _load_rdap_bootstrap() — parses IANA bootstrap JSON
  - _rdap_lookup() — builds URL, falls back on unknown TLD
  - _parse_registration_date() — extracts date + registrar from RDAP response
  - _compute_age_days() — date arithmetic
  - _mx_lookup() / _txt_lookup() — DNS helpers (dns module mocked)
  - enrich_domains() — threat tag logic
  - run_domain_enrichment() — end-to-end with file output
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cirrus.analysis.domain_enrichment import (
    DomainEnrichment,
    _compute_age_days,
    _extract_domains_from_case,
    _load_rdap_bootstrap,
    _mx_lookup,
    _parse_registration_date,
    _rdap_lookup,
    _txt_lookup,
    enrich_domains,
    run_domain_enrichment,
)


# ── _extract_domains_from_case ─────────────────────────────────────────────────

class TestExtractDomainsFromCase:
    def _write(self, tmp_path: Path, filename: str, records: list) -> None:
        (tmp_path / filename).write_text(json.dumps(records), encoding="utf-8")

    def test_extracts_forwards_to_email(self, tmp_path: Path):
        self._write(tmp_path, "mailbox_rules.json", [
            {"_iocFlags": ["FORWARDS_TO:attacker@evil.com"]}
        ])
        domains = _extract_domains_from_case(tmp_path)
        assert "evil.com" in domains

    def test_extracts_external_smtp_forward(self, tmp_path: Path):
        self._write(tmp_path, "mail_forwarding.json", [
            {"_iocFlags": ["EXTERNAL_SMTP_FORWARD:user@phish.net"]}
        ])
        domains = _extract_domains_from_case(tmp_path)
        assert "phish.net" in domains

    def test_extracts_external_email_otp(self, tmp_path: Path):
        self._write(tmp_path, "mfa_methods.json", [
            {"_iocFlags": ["EXTERNAL_EMAIL_OTP:burner-domain.io"]}
        ])
        domains = _extract_domains_from_case(tmp_path)
        assert "burner-domain.io" in domains

    def test_extracts_forwarding_address(self, tmp_path: Path):
        self._write(tmp_path, "mail_forwarding.json", [
            {"_iocFlags": ["FORWARDING_ADDRESS:redirect@other.org"]}
        ])
        domains = _extract_domains_from_case(tmp_path)
        assert "other.org" in domains

    def test_bare_domain_flag(self, tmp_path: Path):
        self._write(tmp_path, "mfa_methods.json", [
            {"_iocFlags": ["EXTERNAL_EMAIL_OTP:suspicious-domain.ru"]}
        ])
        domains = _extract_domains_from_case(tmp_path)
        assert "suspicious-domain.ru" in domains

    def test_domain_lowercased(self, tmp_path: Path):
        self._write(tmp_path, "mailbox_rules.json", [
            {"_iocFlags": ["FORWARDS_TO:Bob@EVIL.COM"]}
        ])
        domains = _extract_domains_from_case(tmp_path)
        assert "evil.com" in domains

    def test_deduplicates_across_files(self, tmp_path: Path):
        self._write(tmp_path, "file1.json", [
            {"_iocFlags": ["FORWARDS_TO:a@evil.com"]}
        ])
        self._write(tmp_path, "file2.json", [
            {"_iocFlags": ["FORWARDS_TO:b@evil.com"]}
        ])
        domains = _extract_domains_from_case(tmp_path)
        assert len([d for d in domains if d == "evil.com"]) == 1

    def test_ignores_non_matching_flags(self, tmp_path: Path):
        self._write(tmp_path, "audit_logs.json", [
            {"_iocFlags": ["HIGH_PRIV_ROLE:Global Administrator", "PUBLIC_IP:1.2.3.4"]}
        ])
        domains = _extract_domains_from_case(tmp_path)
        assert domains == set()

    def test_empty_case_dir_returns_empty(self, tmp_path: Path):
        assert _extract_domains_from_case(tmp_path) == set()

    def test_malformed_json_skipped(self, tmp_path: Path):
        (tmp_path / "bad.json").write_text("{{not json}}", encoding="utf-8")
        domains = _extract_domains_from_case(tmp_path)
        assert isinstance(domains, set)

    def test_non_list_json_skipped(self, tmp_path: Path):
        (tmp_path / "audit_logs.json").write_text(
            json.dumps({"_iocFlags": ["FORWARDS_TO:x@y.com"]}), encoding="utf-8"
        )
        domains = _extract_domains_from_case(tmp_path)
        assert "y.com" not in domains

    def test_flag_without_dot_excluded(self, tmp_path: Path):
        self._write(tmp_path, "mfa.json", [
            {"_iocFlags": ["EXTERNAL_EMAIL_OTP:nodot"]}
        ])
        domains = _extract_domains_from_case(tmp_path)
        assert "nodot" not in domains


# ── _load_rdap_bootstrap ────────────────────────────────────────────────────────

class TestLoadRdapBootstrap:
    def _make_session(self, data: dict):
        session = MagicMock()
        resp = MagicMock()
        resp.json.return_value = data
        resp.raise_for_status.return_value = None
        session.get.return_value = resp
        return session

    def test_parses_tld_map(self):
        session = self._make_session({
            "services": [
                [["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
                [["org"], ["https://rdap.pir.org/"]],
            ]
        })
        tld_map = _load_rdap_bootstrap(session)
        assert tld_map.get("com") == "https://rdap.verisign.com/com/v1/"
        assert tld_map.get("org") == "https://rdap.pir.org/"

    def test_returns_empty_on_network_error(self):
        session = MagicMock()
        session.get.side_effect = Exception("network error")
        tld_map = _load_rdap_bootstrap(session)
        assert tld_map == {}

    def test_returns_empty_on_bad_json(self):
        session = MagicMock()
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        resp.json.side_effect = ValueError("bad json")
        session.get.return_value = resp
        tld_map = _load_rdap_bootstrap(session)
        assert tld_map == {}

    def test_uses_last_url_from_list(self):
        session = self._make_session({
            "services": [
                [["io"], ["https://primary.io/", "https://fallback.io/"]],
            ]
        })
        tld_map = _load_rdap_bootstrap(session)
        assert tld_map["io"] == "https://fallback.io/"


# ── _rdap_lookup ────────────────────────────────────────────────────────────────

class TestRdapLookup:
    def _make_session(self, response_data: dict):
        session = MagicMock()
        resp = MagicMock()
        resp.json.return_value = response_data
        resp.raise_for_status.return_value = None
        session.get.return_value = resp
        return session

    def test_raises_on_unknown_tld(self):
        session = self._make_session({})
        with pytest.raises(ValueError, match="No RDAP server"):
            _rdap_lookup(session, "example.xyz", {})

    def test_builds_correct_url(self):
        session = self._make_session({"events": [], "entities": []})
        tld_map = {"com": "https://rdap.verisign.com/com/v1/"}
        _rdap_lookup(session, "evil.com", tld_map)
        call_url = session.get.call_args[0][0]
        assert "evil.com" in call_url
        assert call_url.startswith("https://rdap.verisign.com")

    def test_returns_parsed_json(self):
        rdap_resp = {"events": [{"eventAction": "registration", "eventDate": "2025-01-01T00:00:00Z"}]}
        session = self._make_session(rdap_resp)
        tld_map = {"com": "https://rdap.verisign.com/com/v1/"}
        result = _rdap_lookup(session, "example.com", tld_map)
        assert "events" in result


# ── _parse_registration_date ───────────────────────────────────────────────────

class TestParseRegistrationDate:
    def _rdap(self, events=None, entities=None):
        return {"events": events or [], "entities": entities or []}

    def test_extracts_registration_date(self):
        rdap = self._rdap(events=[
            {"eventAction": "registration", "eventDate": "2023-06-15T12:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2024-01-01T00:00:00Z"},
        ])
        date, _ = _parse_registration_date(rdap)
        assert date == "2023-06-15T12:00:00Z"

    def test_returns_empty_when_no_registration_event(self):
        rdap = self._rdap(events=[{"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"}])
        date, _ = _parse_registration_date(rdap)
        assert date == ""

    def test_extracts_registrar_from_vcard(self):
        rdap = self._rdap(entities=[{
            "roles": ["registrar"],
            "vcardArray": ["vcard", [
                ["version", {}, "text", "4.0"],
                ["fn", {}, "text", "GoDaddy LLC"],
            ]],
        }])
        _, registrar = _parse_registration_date(rdap)
        assert registrar == "GoDaddy LLC"

    def test_falls_back_to_handle_when_no_vcard_fn(self):
        rdap = self._rdap(entities=[{
            "roles": ["registrar"],
            "handle": "HANDLE-123",
            "vcardArray": ["vcard", []],
        }])
        _, registrar = _parse_registration_date(rdap)
        assert registrar == "HANDLE-123"

    def test_ignores_non_registrar_entities(self):
        rdap = self._rdap(entities=[{
            "roles": ["technical"],
            "vcardArray": ["vcard", [
                ["fn", {}, "text", "Tech Contact"],
            ]],
        }])
        _, registrar = _parse_registration_date(rdap)
        assert registrar == ""

    def test_empty_rdap_returns_empty_strings(self):
        date, registrar = _parse_registration_date({})
        assert date == ""
        assert registrar == ""


# ── _compute_age_days ──────────────────────────────────────────────────────────

class TestComputeAgeDays:
    def test_old_domain_has_large_age(self):
        old_date = (datetime.now(timezone.utc) - timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")
        age = _compute_age_days(old_date)
        assert age is not None
        assert age >= 364

    def test_new_domain_has_small_age(self):
        new_date = (datetime.now(timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        age = _compute_age_days(new_date)
        assert age is not None
        assert age <= 6

    def test_empty_string_returns_none(self):
        assert _compute_age_days("") is None

    def test_invalid_date_returns_none(self):
        assert _compute_age_days("not-a-date") is None


# ── _mx_lookup / _txt_lookup ────────────────────────────────────────────────────

class TestMxLookup:
    def _make_mx_answer(self, *hostnames: str):
        answers = []
        for h in hostnames:
            m = MagicMock()
            m.exchange.__str__ = lambda s, h=h: h + "."
            answers.append(m)
        return answers

    def test_returns_sorted_mx_hostnames(self):
        answers = self._make_mx_answer("mx2.example.com", "mx1.example.com")
        with patch("cirrus.analysis.domain_enrichment._DNS_AVAILABLE", True):
            with patch("cirrus.analysis.domain_enrichment.dns.resolver.resolve", return_value=answers):
                result = _mx_lookup("example.com")
        assert result == sorted(result)

    def test_returns_empty_list_on_dns_error(self):
        with patch("cirrus.analysis.domain_enrichment._DNS_AVAILABLE", True):
            with patch("cirrus.analysis.domain_enrichment.dns.resolver.resolve",
                       side_effect=Exception("DNS error")):
                result = _mx_lookup("example.com")
        assert result == []

    def test_returns_empty_when_dns_not_available(self):
        with patch("cirrus.analysis.domain_enrichment._DNS_AVAILABLE", False):
            result = _mx_lookup("example.com")
        assert result == []


class TestTxtLookup:
    def _make_txt_answer(self, txt: str):
        record = MagicMock()
        record.strings = [txt.encode("utf-8")]
        return record

    def test_spf_found_returns_true(self):
        with patch("cirrus.analysis.domain_enrichment._DNS_AVAILABLE", True):
            with patch("cirrus.analysis.domain_enrichment.dns.resolver.resolve",
                       return_value=[self._make_txt_answer("v=spf1 include:_spf.google.com ~all")]):
                result = _txt_lookup("example.com", "v=spf1")
        assert result is True

    def test_spf_absent_returns_false(self):
        with patch("cirrus.analysis.domain_enrichment._DNS_AVAILABLE", True):
            with patch("cirrus.analysis.domain_enrichment.dns.resolver.resolve",
                       return_value=[self._make_txt_answer("some other TXT record")]):
                result = _txt_lookup("example.com", "v=spf1")
        assert result is False

    def test_nxdomain_returns_false(self):
        import dns.resolver as real_resolver
        with patch("cirrus.analysis.domain_enrichment._DNS_AVAILABLE", True):
            with patch("cirrus.analysis.domain_enrichment.dns.resolver.resolve",
                       side_effect=real_resolver.NXDOMAIN()):
                result = _txt_lookup("example.com", "v=spf1")
        assert result is False

    def test_returns_none_when_dns_not_available(self):
        with patch("cirrus.analysis.domain_enrichment._DNS_AVAILABLE", False):
            result = _txt_lookup("example.com", "v=spf1")
        assert result is None


# ── enrich_domains — threat tag logic ─────────────────────────────────────────

class TestEnrichDomainsThreatTags:
    """
    Test threat tag emission by patching RDAP/DNS internals so no network
    calls are made.
    """

    def _enrich_one(
        self,
        domain: str = "evil.com",
        age_days: int | None = None,
        mx_records: list[str] | None = None,
        has_spf: bool | None = True,
        has_dmarc: bool | None = True,
    ) -> DomainEnrichment:
        mx = mx_records if mx_records is not None else ["mail.evil.com"]
        _fake_rdap = {"events": [], "entities": []}
        _fake_reg_date = "2025-01-01T00:00:00Z" if age_days is not None else ""

        with (
            patch("cirrus.analysis.domain_enrichment.requests.Session"),
            patch("cirrus.analysis.domain_enrichment._load_rdap_bootstrap", return_value={"com": "https://rdap.test/"}),
            patch("cirrus.analysis.domain_enrichment._rdap_lookup", return_value=_fake_rdap),
            patch("cirrus.analysis.domain_enrichment._parse_registration_date", return_value=(_fake_reg_date, "TestRegistrar")),
            patch("cirrus.analysis.domain_enrichment._compute_age_days", return_value=age_days),
            patch("cirrus.analysis.domain_enrichment._mx_lookup", return_value=mx),
            patch("cirrus.analysis.domain_enrichment._txt_lookup", side_effect=[has_spf, has_dmarc]),
            patch("cirrus.analysis.domain_enrichment.time.sleep"),
        ):
            results = enrich_domains({domain})

        return results[domain]

    def test_new_domain_flagged(self):
        result = self._enrich_one(age_days=10)
        assert any("NEW_DOMAIN" in t for t in result.threat_summary)

    def test_old_domain_not_flagged_for_age(self):
        result = self._enrich_one(age_days=180)
        assert not any("NEW_DOMAIN" in t for t in result.threat_summary)

    def test_consumer_mail_mx_flagged(self):
        # Root of "inbound.gmail.com" → "gmail.com" which IS in _CONSUMER_MAIL_DOMAINS
        result = self._enrich_one(mx_records=["inbound.gmail.com"])
        assert "CONSUMER_MAIL_MX" in result.threat_summary

    def test_no_mx_flagged(self):
        result = self._enrich_one(mx_records=[])
        assert "NO_MX" in result.threat_summary

    def test_no_spf_flagged(self):
        result = self._enrich_one(has_spf=False)
        assert "NO_SPF" in result.threat_summary

    def test_no_dmarc_flagged(self):
        result = self._enrich_one(has_dmarc=False)
        assert "NO_DMARC" in result.threat_summary

    def test_spf_present_not_flagged(self):
        result = self._enrich_one(has_spf=True)
        assert "NO_SPF" not in result.threat_summary

    def test_unknown_spf_not_flagged(self):
        # has_spf=None means lookup failed — should not flag NO_SPF
        result = self._enrich_one(has_spf=None, has_dmarc=None)
        assert "NO_SPF" not in result.threat_summary
        assert "NO_DMARC" not in result.threat_summary

    def test_multiple_tags_accumulated(self):
        result = self._enrich_one(
            age_days=5,
            mx_records=["inbound.gmail.com"],
            has_spf=False,
            has_dmarc=False,
        )
        assert len(result.threat_summary) >= 3


# ── run_domain_enrichment ──────────────────────────────────────────────────────

class TestRunDomainEnrichment:
    def test_no_domains_writes_empty_output(self, tmp_path: Path):
        result = run_domain_enrichment(tmp_path)
        assert result["total_domains"] == 0
        assert (tmp_path / "domain_enrichment.json").exists()

    def test_output_file_written(self, tmp_path: Path):
        (tmp_path / "mailbox_rules.json").write_text(
            json.dumps([{"_iocFlags": ["FORWARDS_TO:attacker@evil.com"]}]),
            encoding="utf-8",
        )
        with (
            patch("cirrus.analysis.domain_enrichment.requests.Session"),
            patch("cirrus.analysis.domain_enrichment._load_rdap_bootstrap", return_value={}),
            patch("cirrus.analysis.domain_enrichment._rdap_lookup", side_effect=ValueError("no RDAP")),
            patch("cirrus.analysis.domain_enrichment._compute_age_days", return_value=200),
            patch("cirrus.analysis.domain_enrichment._mx_lookup", return_value=["mail.evil.com"]),
            patch("cirrus.analysis.domain_enrichment._txt_lookup", return_value=True),
            patch("cirrus.analysis.domain_enrichment.time.sleep"),
        ):
            result = run_domain_enrichment(tmp_path)

        out_path = tmp_path / "domain_enrichment.json"
        assert out_path.exists()
        written = json.loads(out_path.read_text(encoding="utf-8"))
        assert written["total_domains"] == 1
        assert "evil.com" in written["domains"]

    def test_suspicious_count_correct(self, tmp_path: Path):
        (tmp_path / "mfa_methods.json").write_text(
            json.dumps([{"_iocFlags": ["EXTERNAL_EMAIL_OTP:new-evil.com"]}]),
            encoding="utf-8",
        )
        with (
            patch("cirrus.analysis.domain_enrichment.requests.Session"),
            patch("cirrus.analysis.domain_enrichment._load_rdap_bootstrap", return_value={}),
            patch("cirrus.analysis.domain_enrichment._rdap_lookup", side_effect=ValueError("no RDAP")),
            patch("cirrus.analysis.domain_enrichment._compute_age_days", return_value=3),  # new domain
            patch("cirrus.analysis.domain_enrichment._mx_lookup", return_value=[]),
            patch("cirrus.analysis.domain_enrichment._txt_lookup", return_value=False),
            patch("cirrus.analysis.domain_enrichment.time.sleep"),
        ):
            result = run_domain_enrichment(tmp_path)

        assert result["suspicious_count"] == 1

    def test_on_progress_callback_called(self, tmp_path: Path):
        (tmp_path / "mailbox_rules.json").write_text(
            json.dumps([{"_iocFlags": ["FORWARDS_TO:x@foo.io"]}]),
            encoding="utf-8",
        )
        messages: list[str] = []
        with (
            patch("cirrus.analysis.domain_enrichment.requests.Session"),
            patch("cirrus.analysis.domain_enrichment._load_rdap_bootstrap", return_value={}),
            patch("cirrus.analysis.domain_enrichment._rdap_lookup", side_effect=ValueError("no RDAP")),
            patch("cirrus.analysis.domain_enrichment._compute_age_days", return_value=100),
            patch("cirrus.analysis.domain_enrichment._mx_lookup", return_value=[]),
            patch("cirrus.analysis.domain_enrichment._txt_lookup", return_value=None),
            patch("cirrus.analysis.domain_enrichment.time.sleep"),
        ):
            run_domain_enrichment(tmp_path, on_progress=messages.append)

        assert len(messages) >= 1
