"""
Tests for cirrus/analysis/ip_enrichment.py

Covers:
  - IPEnrichment dataclass properties
  - extract_ips_from_case() scanning
  - _enrich_batch_ipapi() parsing (responses mocked via monkeypatch)
  - _enrich_single_abuseipdb() parsing (responses mocked)
  - enrich_ips_batch() pipeline logic
  - run_enrichment() writes ip_enrichment.json
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cirrus.analysis.ip_enrichment import (
    IPEnrichment,
    _enrich_batch_ipapi,
    _enrich_single_abuseipdb,
    _enrich_single_virustotal,
    enrich_ips_batch,
    extract_ips_from_case,
    run_enrichment,
)


# ── IPEnrichment dataclass ─────────────────────────────────────────────────────

class TestIPEnrichmentDataclass:
    def test_threat_summary_empty_by_default(self):
        e = IPEnrichment(ip="1.2.3.4")
        assert e.threat_summary == []

    def test_threat_summary_tor(self):
        e = IPEnrichment(ip="1.2.3.4", is_tor=True)
        assert "TOR_EXIT_NODE" in e.threat_summary

    def test_threat_summary_datacenter(self):
        e = IPEnrichment(ip="1.2.3.4", is_datacenter=True)
        assert "DATACENTER/HOSTING" in e.threat_summary

    def test_threat_summary_proxy(self):
        e = IPEnrichment(ip="1.2.3.4", is_proxy=True)
        assert "PROXY/VPN" in e.threat_summary

    def test_threat_summary_abuse_score_above_threshold(self):
        e = IPEnrichment(ip="1.2.3.4", abuse_score=50)
        assert any("ABUSE_SCORE" in t for t in e.threat_summary)

    def test_threat_summary_abuse_score_below_threshold(self):
        e = IPEnrichment(ip="1.2.3.4", abuse_score=10)
        assert not any("ABUSE_SCORE" in t for t in e.threat_summary)

    def test_threat_summary_abuse_score_none_not_included(self):
        e = IPEnrichment(ip="1.2.3.4", abuse_score=None)
        assert not any("ABUSE_SCORE" in t for t in e.threat_summary)

    def test_threat_summary_vt_malicious(self):
        e = IPEnrichment(ip="1.2.3.4", vt_malicious=3)
        assert any("VT_MALICIOUS" in t for t in e.threat_summary)

    def test_threat_summary_vt_malicious_zero_not_included(self):
        e = IPEnrichment(ip="1.2.3.4", vt_malicious=0)
        assert not any("VT_MALICIOUS" in t for t in e.threat_summary)

    def test_threat_summary_vt_malicious_none_not_included(self):
        e = IPEnrichment(ip="1.2.3.4", vt_malicious=None)
        assert not any("VT_MALICIOUS" in t for t in e.threat_summary)

    def test_is_suspicious_false_by_default(self):
        assert not IPEnrichment(ip="1.2.3.4").is_suspicious

    def test_is_suspicious_true_when_tor(self):
        assert IPEnrichment(ip="1.2.3.4", is_tor=True).is_suspicious

    def test_is_suspicious_true_when_datacenter(self):
        assert IPEnrichment(ip="1.2.3.4", is_datacenter=True).is_suspicious

    def test_is_suspicious_true_when_high_abuse_score(self):
        assert IPEnrichment(ip="1.2.3.4", abuse_score=80).is_suspicious

    def test_multiple_threat_indicators(self):
        e = IPEnrichment(ip="1.2.3.4", is_tor=True, is_datacenter=True, abuse_score=90)
        assert len(e.threat_summary) == 3


# ── extract_ips_from_case ──────────────────────────────────────────────────────

class TestExtractIPsFromCase:
    def test_extracts_ip_from_ipaddress_field(self, tmp_path: Path):
        data = [{"userPrincipalName": "user@c.com", "ipAddress": "8.8.8.8"}]
        (tmp_path / "signin_logs.json").write_text(json.dumps(data))
        ips = extract_ips_from_case(tmp_path)
        assert "8.8.8.8" in ips

    def test_extracts_ip_from_iocflags(self, tmp_path: Path):
        data = [{"_iocFlags": ["PUBLIC_IP:1.2.3.4", "SOME_OTHER_FLAG"]}]
        (tmp_path / "audit_logs.json").write_text(json.dumps(data))
        ips = extract_ips_from_case(tmp_path)
        assert "1.2.3.4" in ips

    def test_skips_private_ips(self, tmp_path: Path):
        data = [{"ipAddress": "192.168.1.1"}, {"ipAddress": "10.0.0.5"}]
        (tmp_path / "signin_logs.json").write_text(json.dumps(data))
        ips = extract_ips_from_case(tmp_path)
        assert "192.168.1.1" not in ips
        assert "10.0.0.5" not in ips

    def test_skips_enrichment_output_file(self, tmp_path: Path):
        # ip_enrichment.json should not be scanned (avoid self-referential loop)
        data = {"ips": {"5.5.5.5": {"ipAddress": "5.5.5.5"}}}
        (tmp_path / "ip_enrichment.json").write_text(json.dumps(data))
        ips = extract_ips_from_case(tmp_path)
        assert "5.5.5.5" not in ips

    def test_skips_ioc_correlation_file(self, tmp_path: Path):
        data = [{"ipAddress": "6.6.6.6"}]
        (tmp_path / "ioc_correlation.json").write_text(json.dumps(data))
        ips = extract_ips_from_case(tmp_path)
        assert "6.6.6.6" not in ips

    def test_deduplicates_ips(self, tmp_path: Path):
        data = [
            {"ipAddress": "8.8.8.8"},
            {"ipAddress": "8.8.8.8"},
            {"_iocFlags": ["PUBLIC_IP:8.8.8.8"]},
        ]
        (tmp_path / "signin_logs.json").write_text(json.dumps(data))
        ips = extract_ips_from_case(tmp_path)
        assert len([ip for ip in ips if ip == "8.8.8.8"]) == 1

    def test_empty_case_returns_empty_set(self, tmp_path: Path):
        ips = extract_ips_from_case(tmp_path)
        assert ips == set()

    def test_malformed_json_skipped(self, tmp_path: Path):
        (tmp_path / "bad.json").write_text("not valid json {{{")
        ips = extract_ips_from_case(tmp_path)
        assert isinstance(ips, set)

    def test_non_list_json_skipped_gracefully(self, tmp_path: Path):
        (tmp_path / "signin_logs.json").write_text(json.dumps({"ipAddress": "7.7.7.7"}))
        ips = extract_ips_from_case(tmp_path)
        # Top-level dict is not a list of records — should produce empty set (no crash)
        assert isinstance(ips, set)

    def test_multiple_files_combined(self, tmp_path: Path):
        (tmp_path / "signin_logs.json").write_text(json.dumps([{"ipAddress": "1.1.1.1"}]))
        (tmp_path / "audit_logs.json").write_text(json.dumps([{"_iocFlags": ["PUBLIC_IP:2.2.2.2"]}]))
        ips = extract_ips_from_case(tmp_path)
        assert "1.1.1.1" in ips
        assert "2.2.2.2" in ips


# ── _enrich_batch_ipapi ────────────────────────────────────────────────────────

class TestEnrichBatchIpapi:
    def _make_session(self, response_data):
        session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.json.return_value = response_data
        mock_resp.raise_for_status.return_value = None
        session.post.return_value = mock_resp
        return session

    def test_successful_lookup(self):
        session = self._make_session([{
            "query": "8.8.8.8",
            "status": "success",
            "country": "United States",
            "countryCode": "US",
            "city": "Ashburn",
            "org": "Google LLC",
            "isp": "Google LLC",
            "as": "AS15169 Google LLC",
            "proxy": False,
            "hosting": True,
            "tor": False,
        }])
        results = _enrich_batch_ipapi(["8.8.8.8"], session)
        assert "8.8.8.8" in results
        e = results["8.8.8.8"]
        assert e.country_code == "US"
        assert e.country_name == "United States"
        assert e.city == "Ashburn"
        assert e.asn == "AS15169"
        assert e.is_datacenter is True
        assert e.is_tor is False

    def test_failed_lookup_sets_error(self):
        session = self._make_session([{
            "query": "1.2.3.4",
            "status": "fail",
            "message": "private range",
        }])
        results = _enrich_batch_ipapi(["1.2.3.4"], session)
        assert results["1.2.3.4"].error != ""

    def test_api_exception_sets_error_for_all_ips(self):
        session = MagicMock()
        session.post.side_effect = Exception("network error")
        results = _enrich_batch_ipapi(["1.1.1.1", "2.2.2.2"], session)
        assert results["1.1.1.1"].error != ""
        assert results["2.2.2.2"].error != ""

    def test_missing_ip_from_response_gets_error(self):
        # Response omits one IP
        session = self._make_session([{
            "query": "8.8.8.8",
            "status": "success",
            "country": "US", "countryCode": "US", "city": "",
            "org": "", "isp": "", "as": "",
            "proxy": False, "hosting": False, "tor": False,
        }])
        results = _enrich_batch_ipapi(["8.8.8.8", "9.9.9.9"], session)
        assert results["9.9.9.9"].error != ""

    def test_tor_flag_parsed(self):
        session = self._make_session([{
            "query": "5.5.5.5",
            "status": "success",
            "country": "DE", "countryCode": "DE", "city": "Berlin",
            "org": "", "isp": "", "as": "AS12345",
            "proxy": False, "hosting": False, "tor": True,
        }])
        results = _enrich_batch_ipapi(["5.5.5.5"], session)
        assert results["5.5.5.5"].is_tor is True


# ── _enrich_single_abuseipdb ───────────────────────────────────────────────────

class TestEnrichSingleAbuseIPDB:
    def _make_session(self, status_code, body):
        session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = status_code
        mock_resp.json.return_value = body
        mock_resp.raise_for_status.return_value = None
        session.get.return_value = mock_resp
        return session

    def test_successful_lookup(self):
        session = self._make_session(200, {
            "data": {"abuseConfidenceScore": 42, "totalReports": 7}
        })
        score, reports, err = _enrich_single_abuseipdb("1.2.3.4", "key123", session)
        assert score == 42
        assert reports == 7
        assert err == ""

    def test_zero_score(self):
        session = self._make_session(200, {
            "data": {"abuseConfidenceScore": 0, "totalReports": 0}
        })
        score, reports, err = _enrich_single_abuseipdb("1.2.3.4", "key123", session)
        assert score == 0
        assert reports == 0
        assert err == ""

    def test_rate_limit_returns_error(self):
        session = self._make_session(429, {})
        score, reports, err = _enrich_single_abuseipdb("1.2.3.4", "key123", session)
        assert score is None
        assert "rate limit" in err.lower()

    def test_invalid_api_key_returns_error(self):
        session = self._make_session(401, {})
        score, reports, err = _enrich_single_abuseipdb("1.2.3.4", "badkey", session)
        assert score is None
        assert "invalid api key" in err.lower() or "key" in err.lower()

    def test_network_exception_returns_error(self):
        session = MagicMock()
        session.get.side_effect = Exception("timeout")
        score, reports, err = _enrich_single_abuseipdb("1.2.3.4", "key123", session)
        assert score is None
        assert err != ""


# ── enrich_ips_batch ───────────────────────────────────────────────────────────

class TestEnrichIpsBatch:
    def test_empty_input_returns_empty_dict(self):
        result = enrich_ips_batch(set())
        assert result == {}

    def test_no_abuseipdb_key_skips_abuseipdb(self):
        """When no key is provided, AbuseIPDB must not be queried."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = [{
            "query": "8.8.8.8", "status": "success",
            "country": "US", "countryCode": "US", "city": "Ashburn",
            "org": "Google", "isp": "Google", "as": "AS15169",
            "proxy": False, "hosting": True, "tor": False,
        }]
        mock_resp.raise_for_status.return_value = None

        with patch("cirrus.analysis.ip_enrichment.requests.Session") as MockSession:
            mock_session_inst = MagicMock()
            mock_session_inst.post.return_value = mock_resp
            MockSession.return_value = mock_session_inst

            result = enrich_ips_batch({"8.8.8.8"}, abuseipdb_key=None)

        # post (ip-api) called, get (abuseipdb) not called
        mock_session_inst.post.assert_called_once()
        mock_session_inst.get.assert_not_called()
        assert "8.8.8.8" in result

    def test_abuseipdb_queried_when_key_provided(self):
        ipapi_resp = MagicMock()
        ipapi_resp.raise_for_status.return_value = None
        ipapi_resp.json.return_value = [{
            "query": "1.1.1.1", "status": "success",
            "country": "AU", "countryCode": "AU", "city": "Sydney",
            "org": "Cloudflare", "isp": "Cloudflare", "as": "AS13335",
            "proxy": False, "hosting": True, "tor": False,
        }]
        abuse_resp = MagicMock()
        abuse_resp.status_code = 200
        abuse_resp.raise_for_status.return_value = None
        abuse_resp.json.return_value = {"data": {"abuseConfidenceScore": 5, "totalReports": 1}}

        with patch("cirrus.analysis.ip_enrichment.requests.Session") as MockSession:
            with patch("cirrus.analysis.ip_enrichment.time.sleep"):
                mock_session_inst = MagicMock()
                mock_session_inst.post.return_value = ipapi_resp
                mock_session_inst.get.return_value = abuse_resp
                MockSession.return_value = mock_session_inst

                result = enrich_ips_batch({"1.1.1.1"}, abuseipdb_key="testkey")

        mock_session_inst.get.assert_called_once()
        assert result["1.1.1.1"].abuse_score == 5

    def test_on_progress_callback_called(self):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = [{
            "query": "8.8.8.8", "status": "success",
            "country": "US", "countryCode": "US", "city": "",
            "org": "", "isp": "", "as": "",
            "proxy": False, "hosting": False, "tor": False,
        }]

        messages: list[str] = []
        with patch("cirrus.analysis.ip_enrichment.requests.Session") as MockSession:
            mock_session_inst = MagicMock()
            mock_session_inst.post.return_value = mock_resp
            MockSession.return_value = mock_session_inst
            enrich_ips_batch({"8.8.8.8"}, on_progress=messages.append)

        assert len(messages) >= 1


# ── run_enrichment ─────────────────────────────────────────────────────────────

class TestRunEnrichment:
    def test_no_ips_writes_empty_output(self, tmp_path: Path):
        result = run_enrichment(tmp_path)
        assert result["total_ips"] == 0
        assert (tmp_path / "ip_enrichment.json").exists()

    def test_writes_ip_enrichment_json(self, tmp_path: Path):
        (tmp_path / "signin_logs.json").write_text(
            json.dumps([{"ipAddress": "8.8.8.8"}])
        )
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = [{
            "query": "8.8.8.8", "status": "success",
            "country": "United States", "countryCode": "US", "city": "Ashburn",
            "org": "Google LLC", "isp": "Google", "as": "AS15169 Google",
            "proxy": False, "hosting": True, "tor": False,
        }]

        with patch("cirrus.analysis.ip_enrichment.requests.Session") as MockSession:
            inst = MagicMock()
            inst.post.return_value = mock_resp
            MockSession.return_value = inst
            result = run_enrichment(tmp_path)

        out_path = tmp_path / "ip_enrichment.json"
        assert out_path.exists()
        written = json.loads(out_path.read_text())
        assert written["total_ips"] == 1
        assert "8.8.8.8" in written["ips"]

    def test_suspicious_count_reflects_threat_tags(self, tmp_path: Path):
        (tmp_path / "signin_logs.json").write_text(
            json.dumps([{"ipAddress": "8.8.8.8"}])
        )
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = [{
            "query": "8.8.8.8", "status": "success",
            "country": "US", "countryCode": "US", "city": "",
            "org": "", "isp": "", "as": "",
            "proxy": False, "hosting": True, "tor": False,  # is_datacenter=True → suspicious
        }]

        with patch("cirrus.analysis.ip_enrichment.requests.Session") as MockSession:
            inst = MagicMock()
            inst.post.return_value = mock_resp
            MockSession.return_value = inst
            result = run_enrichment(tmp_path)

        assert result["suspicious_count"] == 1

    def test_output_includes_threat_summary_and_is_suspicious(self, tmp_path: Path):
        (tmp_path / "signin_logs.json").write_text(
            json.dumps([{"ipAddress": "3.3.3.3"}])
        )
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = [{
            "query": "3.3.3.3", "status": "success",
            "country": "NL", "countryCode": "NL", "city": "Amsterdam",
            "org": "Some VPN", "isp": "VPN Inc", "as": "AS99999",
            "proxy": True, "hosting": False, "tor": False,
        }]

        with patch("cirrus.analysis.ip_enrichment.requests.Session") as MockSession:
            inst = MagicMock()
            inst.post.return_value = mock_resp
            MockSession.return_value = inst
            result = run_enrichment(tmp_path)

        ip_data = result["ips"]["3.3.3.3"]
        assert ip_data["is_suspicious"] is True
        assert "PROXY/VPN" in ip_data["threat_summary"]


# ── _enrich_single_virustotal ──────────────────────────────────────────────────

class TestEnrichSingleVirusTotal:
    def _make_session(self, status_code: int, body: dict):
        session = MagicMock()
        resp = MagicMock()
        resp.status_code = status_code
        resp.json.return_value = body
        resp.raise_for_status.return_value = None
        session.get.return_value = resp
        return session

    def test_successful_lookup(self):
        session = self._make_session(200, {
            "data": {"attributes": {"last_analysis_stats": {
                "malicious": 5, "suspicious": 2, "harmless": 40
            }}}
        })
        mal, susp, harm, err = _enrich_single_virustotal("8.8.8.8", "vtkey", session)
        assert mal == 5
        assert susp == 2
        assert harm == 40
        assert err == ""

    def test_zero_detections(self):
        session = self._make_session(200, {
            "data": {"attributes": {"last_analysis_stats": {
                "malicious": 0, "suspicious": 0, "harmless": 72
            }}}
        })
        mal, susp, harm, err = _enrich_single_virustotal("1.1.1.1", "vtkey", session)
        assert mal == 0
        assert err == ""

    def test_404_returns_zeros(self):
        session = self._make_session(404, {})
        mal, susp, harm, err = _enrich_single_virustotal("1.2.3.4", "vtkey", session)
        assert mal == 0
        assert susp == 0
        assert harm == 0
        assert err == ""

    def test_rate_limit_returns_error(self):
        session = self._make_session(429, {})
        mal, susp, harm, err = _enrich_single_virustotal("1.2.3.4", "vtkey", session)
        assert mal is None
        assert "rate limit" in err.lower()

    def test_invalid_api_key_returns_error(self):
        session = self._make_session(401, {})
        mal, susp, harm, err = _enrich_single_virustotal("1.2.3.4", "badkey", session)
        assert mal is None
        assert "invalid api key" in err.lower() or "key" in err.lower()

    def test_network_exception_returns_error(self):
        session = MagicMock()
        session.get.side_effect = Exception("timeout")
        mal, susp, harm, err = _enrich_single_virustotal("1.2.3.4", "vtkey", session)
        assert mal is None
        assert err != ""


# ── enrich_ips_batch — VirusTotal integration ──────────────────────────────────

class TestEnrichIpsBatchVT:
    def _ipapi_response(self, ip: str = "8.8.8.8"):
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        resp.json.return_value = [{
            "query": ip, "status": "success",
            "country": "US", "countryCode": "US", "city": "",
            "org": "", "isp": "", "as": "",
            "proxy": False, "hosting": False, "tor": False,
        }]
        return resp

    def _vt_response(self, malicious: int = 3):
        resp = MagicMock()
        resp.status_code = 200
        resp.raise_for_status.return_value = None
        resp.json.return_value = {
            "data": {"attributes": {"last_analysis_stats": {
                "malicious": malicious, "suspicious": 0, "harmless": 50,
            }}}
        }
        return resp

    def test_vt_queried_when_key_provided(self):
        ipapi_resp = self._ipapi_response("5.5.5.5")
        vt_resp = self._vt_response(malicious=2)

        with patch("cirrus.analysis.ip_enrichment.requests.Session") as MockSession:
            with patch("cirrus.analysis.ip_enrichment.time.sleep"):
                inst = MagicMock()
                inst.post.return_value = ipapi_resp
                inst.get.return_value = vt_resp
                MockSession.return_value = inst

                result = enrich_ips_batch({"5.5.5.5"}, vt_key="vtapikey")

        assert result["5.5.5.5"].vt_malicious == 2

    def test_vt_not_queried_without_key(self):
        ipapi_resp = self._ipapi_response("5.5.5.5")

        with patch("cirrus.analysis.ip_enrichment.requests.Session") as MockSession:
            inst = MagicMock()
            inst.post.return_value = ipapi_resp
            MockSession.return_value = inst

            result = enrich_ips_batch({"5.5.5.5"}, vt_key=None)

        inst.get.assert_not_called()
        assert result["5.5.5.5"].vt_malicious is None

    def test_vt_malicious_shows_in_threat_summary(self):
        ipapi_resp = self._ipapi_response("9.9.9.9")
        vt_resp = self._vt_response(malicious=5)

        with patch("cirrus.analysis.ip_enrichment.requests.Session") as MockSession:
            with patch("cirrus.analysis.ip_enrichment.time.sleep"):
                inst = MagicMock()
                inst.post.return_value = ipapi_resp
                inst.get.return_value = vt_resp
                MockSession.return_value = inst

                result = enrich_ips_batch({"9.9.9.9"}, vt_key="vtapikey")

        assert any("VT_MALICIOUS" in t for t in result["9.9.9.9"].threat_summary)

    def test_run_enrichment_passes_vt_key(self, tmp_path: Path):
        (tmp_path / "signin_logs.json").write_text(
            json.dumps([{"ipAddress": "7.7.7.7"}])
        )
        ipapi_resp = self._ipapi_response("7.7.7.7")
        vt_resp = self._vt_response(malicious=0)

        with patch("cirrus.analysis.ip_enrichment.requests.Session") as MockSession:
            with patch("cirrus.analysis.ip_enrichment.time.sleep"):
                inst = MagicMock()
                inst.post.return_value = ipapi_resp
                inst.get.return_value = vt_resp
                MockSession.return_value = inst

                result = run_enrichment(tmp_path, vt_key="vtkey")

        assert result["vt_used"] is True
        assert "7.7.7.7" in result["ips"]

    def test_run_enrichment_vt_used_false_without_key(self, tmp_path: Path):
        (tmp_path / "signin_logs.json").write_text(
            json.dumps([{"ipAddress": "2.2.2.2"}])
        )
        ipapi_resp = self._ipapi_response("2.2.2.2")

        with patch("cirrus.analysis.ip_enrichment.requests.Session") as MockSession:
            inst = MagicMock()
            inst.post.return_value = ipapi_resp
            MockSession.return_value = inst

            result = run_enrichment(tmp_path)

        assert result.get("vt_used") is False
