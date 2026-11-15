"""Automation layer: doctor, deterministic pipelines, menu utilities (all offline)."""
from __future__ import annotations

import os
import unittest

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
