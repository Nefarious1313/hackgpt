"""Automation layer: doctor, deterministic pipelines, menu utilities (all offline)."""
from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from hackgpt import automation as A
from hackgpt import config as C

from .helpers import FakeConsole


def _cfg() -> dict:
    return {"model": "test/model", "base_url": "https://example.test/v1",
            "enforce_scope": True, "scope": [], "timeout_default": 5,
            "user_agent": "hackgpt-test", "auth_path": C.DEFAULT_CONFIG["auth_path"]}


def _session(name: str = "auto-test") -> dict:
    return {"name": name, "objective": "", "messages": [], "findings": [],
            "targets": [], "credentials": [], "actions": [], "artifacts": []}


class Doctor(unittest.TestCase):
    def test_returns_bool_without_raising(self):
        self.assertIsInstance(A.doctor(_cfg(), fix=False, console=FakeConsole()), bool)


class AutoEngagement(unittest.TestCase):
    def test_dry_run_localhost(self):
        cfg, sess, console = _cfg(), _session(), FakeConsole()
        summary = A.auto_engagement("127.0.0.1", cfg, sess, console, dry_run=True)
        self.assertEqual(summary["target"], "127.0.0.1")
        self.assertTrue(C.target_in_scope("127.0.0.1", cfg["scope"]))
        self.assertEqual(summary["open_ports"], [])
        self.assertEqual(summary["web"], [])
        report = os.path.join(C.OUTPUT_DIR, "report-auto-test.md")
        self.assertTrue(os.path.exists(report))

    def test_scope_seeded_for_domain(self):
        cfg, sess, console = _cfg(), _session(), FakeConsole()
        A.quick_scan("example.com", cfg, sess, console, dry_run=True)
        self.assertTrue(C.target_in_scope("example.com", cfg["scope"]))

    def test_url_target_is_normalized(self):
        cfg, sess, console = _cfg(), _session(), FakeConsole()
        summary = A.auto_engagement("https://localhost/some/path", cfg, sess, console, dry_run=True)
        self.assertEqual(summary["target"], "localhost")
        self.assertTrue(C.target_in_scope("localhost", cfg["scope"]))

    def test_web_checks_dry_run(self):
        cfg, sess, console = _cfg(), _session(), FakeConsole()
        out = A.web_checks("example.com", cfg, sess, console, dry_run=True)
        self.assertEqual(out["url"], "http://example.com")

    def test_research_returns_query(self):
        orig_cve, orig_exp = A.h_cve_lookup, A.h_exploit_search
        A.h_cve_lookup = lambda args, ctx: "cve-ok"
        A.h_exploit_search = lambda args, ctx: "exploit-ok"
        try:
            out = A.research("CVE-2021-44228", _cfg(), _session(), FakeConsole())
        finally:
            A.h_cve_lookup, A.h_exploit_search = orig_cve, orig_exp
        self.assertEqual(out["query"], "CVE-2021-44228")


class DnsWatch(unittest.TestCase):
    def test_runs_requested_number_of_polls(self):
        cfg, sess, console = _cfg(), _session(), FakeConsole()
        with patch.object(A, "h_dns_snapshot", side_effect=["baseline created", "DNS changes: added X"]) as snap:
            with patch.object(A.time, "sleep") as sleep:
                result = A.watch_dns("example.com", cfg, sess, console, interval=5, count=2)
        self.assertEqual(result["polls"], 2)
        self.assertEqual(snap.call_count, 2)
        sleep.assert_called_once_with(5)


class Utilities(unittest.TestCase):
    def test_encode(self):
        out = A.utility("encode", {"input": "hi", "op": "encode", "codec": "base64"},
                        _cfg(), _session(), FakeConsole())
        self.assertEqual(out, "aGk=")

    def test_hash(self):
        out = A.utility("hash", {"hash": "a" * 32}, _cfg(), _session(), FakeConsole())
        self.assertIn("MD5", out)

    def test_unknown_utility(self):
        with self.assertRaises(ValueError):
            A.utility("nope", {}, _cfg(), _session(), FakeConsole())


if __name__ == "__main__":
    unittest.main()
