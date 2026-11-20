"""Regression tests for the NVD CVE lookup and offline Metasploit catalog."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from hackgpt import tools as T
from tests.helpers import FakeConsole, make_ctx


NVD_BY_ID = {
    "vulnerabilities": [{
        "cve": {
            "id": "CVE-2021-44228",
            "descriptions": [{"lang": "en", "value": "Log4j JNDI remote code execution"}],
            "metrics": {"cvssMetricV31": [{"cvssData": {
                "baseScore": 10.0, "baseSeverity": "CRITICAL"}}]},
            "published": "2021-12-10T10:15:09.143",
            "references": [{"url": "https://example.test/advisory"}],
        }
    }],
    "totalResults": 1,
}

NVD_SEARCH = {
    "vulnerabilities": [{
        "cve": {
            "id": "CVE-1999-0236",
            "descriptions": [{"lang": "en", "value": "CGI program disclosure"}],
            "metrics": {},
            "published": "1999-01-01T00:00:00.000",
        }
    }],
    "totalResults": 1,
}

NVD_EMPTY = {"vulnerabilities": [], "totalResults": 0}

CVEAWG = {
    "cveMetadata": {"cveId": "CVE-2099-0001", "datePublished": "2099-01-01T00:00:00.000Z"},
    "containers": {"cna": {"descriptions": [{"lang": "en", "value": "future issue"}]}},
}


class CveLookup(unittest.TestCase):
    def test_by_id_uses_nvd_and_reports_cvss(self):
        ctx = make_ctx()
        with patch.object(T, "_http_get_json", return_value=NVD_BY_ID) as get:
            out = T.h_cve_lookup({"query": "CVE-2021-44228"}, ctx)
        self.assertIn("CVE-2021-44228", out)
        self.assertIn("CVSS: 10.0", out)
        self.assertIn("CRITICAL", out)
        self.assertIn("services.nvd.nist.gov", get.call_args.args[0])
        self.assertNotIn("cve.circl.lu", get.call_args.args[0])

    def test_keyword_search_uses_nvd_keyword_search(self):
        ctx = make_ctx()
        with patch.object(T, "_http_get_json", return_value=NVD_SEARCH) as get:
            out = T.h_cve_lookup({"query": "httpd"}, ctx)
        self.assertIn("CVE-1999-0236", out)
        self.assertIn("keywordSearch=httpd", get.call_args.args[0])

    def test_no_results_falls_back_to_cve_program(self):
        ctx = make_ctx()
        with patch.object(T, "_http_get_json", side_effect=[NVD_EMPTY, CVEAWG]) as get:
            out = T.h_cve_lookup({"query": "CVE-2099-0001"}, ctx)
        self.assertIn("CVE-2099-0001", out)
        self.assertIn("cveawg.mitre.org", get.call_args_list[-1].args[0])

    def test_empty_search_result_is_reported(self):
        ctx = make_ctx()
        with patch.object(T, "_http_get_json", return_value=NVD_EMPTY):
            self.assertIn("no CVEs matched", T.h_cve_lookup({"query": "zzzznotreal"}, ctx))

    def test_network_error_is_reported_without_raising(self):
        ctx = make_ctx()
        with patch.object(T, "_http_get_json", side_effect=OSError("offline")):
            self.assertIn("cve_lookup failed", T.h_cve_lookup({"query": "CVE-2021-44228"}, ctx))


class OfflineMsfCatalog(unittest.TestCase):
    def test_search_without_msfconsole_uses_offline_catalog(self):
        ctx = make_ctx()
        with patch.object(T.C, "which", return_value=None):
            out = T.h_msf_catalog({"action": "search", "query": "http", "type": "auxiliary"}, ctx)
        self.assertIn("offline catalog", out)
        self.assertIn("auxiliary/scanner/http/options", out)
        self.assertEqual(ctx.session["actions"][-1]["tool"], "msf_catalog")

    def test_offline_catalog_does_not_match_unknown_service(self):
        ctx = make_ctx()
        with patch.object(T.C, "which", return_value=None):
            out = T.h_msf_catalog({"action": "search", "query": "totallymadeup", "type": "auxiliary"}, ctx)
        self.assertIn("no module matched", out)

    def test_status_still_reports_missing_binary(self):
        with patch.object(T.C, "which", return_value=None):
            self.assertIn("not installed", T.h_msf_catalog({"action": "status"}, make_ctx()))


if __name__ == "__main__":
    unittest.main()
