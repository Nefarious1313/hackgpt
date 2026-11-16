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

    def test_mitm_utility_seeds_scope(self):
        cfg, sess, console = _cfg(), _session("u-mitm"), FakeConsole()
        orig = A.h_mitm_audit
        A.h_mitm_audit = lambda args, ctx: "mitm-ok"
        try:
            out = A.utility("mitm", {"target": "example.com"}, cfg, sess, console)
        finally:
            A.h_mitm_audit = orig
        self.assertEqual(out, "mitm-ok")
        self.assertTrue(C.target_in_scope("example.com", cfg["scope"]))

    def test_msf_utilities_dispatch(self):
        cfg, sess, console = _cfg(), _session("u-msf"), FakeConsole()
        orig_plan, orig_payload = A.h_msf_plan, A.h_msf_payload
        A.h_msf_plan = lambda args, ctx: "plan-ok"
        A.h_msf_payload = lambda args, ctx: "payload-ok"
        try:
            self.assertEqual(A.utility("msf_plan", {}, cfg, sess, console), "plan-ok")
            self.assertEqual(A.utility("msf_payload", {}, cfg, sess, console), "payload-ok")
        finally:
            A.h_msf_plan, A.h_msf_payload = orig_plan, orig_payload

    def test_rpc_utilities_dispatch(self):
        cfg, sess, console = _cfg(), _session("u-rpc"), FakeConsole()
        orig = (A.h_msf_rpc_status, A.h_msf_rpc_run, A.h_msf_rpc_session)
        A.h_msf_rpc_status = lambda args, ctx: "rpc-status-ok"
        A.h_msf_rpc_run = lambda args, ctx: "rpc-run-ok"
        A.h_msf_rpc_session = lambda args, ctx: "rpc-session-ok"
        try:
            self.assertEqual(A.utility("rpc_status", {}, cfg, sess, console), "rpc-status-ok")
            self.assertEqual(A.utility("rpc_run", {}, cfg, sess, console), "rpc-run-ok")
            self.assertEqual(A.utility("rpc_session", {}, cfg, sess, console), "rpc-session-ok")
        finally:
            A.h_msf_rpc_status, A.h_msf_rpc_run, A.h_msf_rpc_session = orig

    def test_unknown_utility(self):
        with self.assertRaises(ValueError):
            A.utility("nope", {}, _cfg(), _session(), FakeConsole())


class FullEngagement(unittest.TestCase):
    def test_dry_run_localhost_offline(self):
        cfg, sess, console = _cfg(), _session("full-dry"), FakeConsole()
        summary = A.full_engagement("127.0.0.1", cfg, sess, console, dry_run=True)
        self.assertEqual(summary["target"], "127.0.0.1")
        self.assertEqual(summary["mitm"], [])
        self.assertEqual(summary["msf"], [])
        self.assertTrue(C.target_in_scope("127.0.0.1", cfg["scope"]))
        report = os.path.join(C.OUTPUT_DIR, "report-full-dry.md")
        self.assertTrue(os.path.exists(report))

    def test_mitm_phase_audits_live_https_endpoints(self):
        cfg, sess, console = _cfg(), _session("auto-mitm"), FakeConsole()
        orig_probe, orig_audit = A.h_http_probe, A.h_mitm_audit
        calls: list[str] = []
        A.h_http_probe = lambda args, ctx: "GET https://127.0.0.1 -> 200 OK"
        A.h_mitm_audit = lambda args, ctx: calls.append(str(args.get("target"))) or "audit-ok"
        try:
            summary = A.auto_engagement("127.0.0.1", cfg, sess, console, dry_run=True, mitm=True)
        finally:
            A.h_http_probe, A.h_mitm_audit = orig_probe, orig_audit
        self.assertIn("127.0.0.1", calls)
        self.assertEqual(summary["mitm"], ["127.0.0.1"])


if __name__ == "__main__":
    unittest.main()
