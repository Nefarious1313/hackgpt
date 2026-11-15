"""Scope engine, target normalization and session/config persistence."""
from __future__ import annotations

import os
import tempfile
import unittest

from hackgpt import config as C


class NormalizeTarget(unittest.TestCase):
    def test_url(self):
        self.assertEqual(C.normalize_target("https://Example.com/path?q=1"), "example.com")

    def test_scheme_and_port(self):
        self.assertEqual(C.normalize_target("http://example.com:8080/"), "example.com")

    def test_userinfo(self):
        self.assertEqual(C.normalize_target("https://user:pw@example.com/"), "example.com")

    def test_bare_host_lowercased(self):
        self.assertEqual(C.normalize_target("EXAMPLE.com"), "example.com")

    def test_ipv6_bracketed(self):
        self.assertEqual(C.normalize_target("http://[2001:db8::1]:80/"), "2001:db8::1")

    def test_empty(self):
        self.assertEqual(C.normalize_target(""), "")


class TargetInScope(unittest.TestCase):
    def setUp(self):
        self.scope = [{"target": "example.com", "added": "x"},
                      {"target": "203.0.113.0/24", "added": "x"}]

    def test_exact_host(self):
        self.assertTrue(C.target_in_scope("example.com", self.scope))

    def test_subdomain_suffix(self):
        self.assertTrue(C.target_in_scope("api.example.com", self.scope))

    def test_unrelated_host(self):
        self.assertFalse(C.target_in_scope("evil.org", self.scope))

    def test_url_is_normalized(self):
        self.assertTrue(C.target_in_scope("https://example.com/login", self.scope))

    def test_cidr_member(self):
        self.assertTrue(C.target_in_scope("203.0.113.42", self.scope))
        self.assertFalse(C.target_in_scope("203.0.114.42", self.scope))

    def test_wildcard_entry(self):
        scope = [{"target": "*.example.com", "added": "x"}]
        self.assertTrue(C.target_in_scope("a.b.example.com", scope))
        self.assertFalse(C.target_in_scope("example.com", scope))

    def test_star_allows_all(self):
        self.assertTrue(C.target_in_scope("anything.test", [{"target": "*", "added": "x"}]))

    def test_empty_scope_denies(self):
        self.assertFalse(C.target_in_scope("example.com", []))

    def test_string_entries(self):
        self.assertTrue(C.target_in_scope("example.com", ["example.com"]))


class RequireScope(unittest.TestCase):
    def test_raises_out_of_scope(self):
        with self.assertRaises(C.ScopeDenied):
            C.require_scope({"enforce_scope": True, "scope": []}, "example.com")

    def test_allows_in_scope(self):
        C.require_scope({"enforce_scope": True, "scope": ["example.com"]}, "example.com")

    def test_disabled_enforcement(self):
        C.require_scope({"enforce_scope": False, "scope": []}, "example.com")


class Persistence(unittest.TestCase):
    def test_config_roundtrip(self):
        path = os.path.join(tempfile.mkdtemp(), "cfg.yaml")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("model: test/model\nscope:\n- target: example.com\n  added: x\n")
        cfg = C.load_config()
        # HACKGPT_HOME is a temp dir for tests; just exercise save/load roundtrip.
        C.save_config({"model": "test/model", "scope": [{"target": "example.com"}]})
        back = C.load_config()
        self.assertEqual(back["model"], "test/model")
        self.assertTrue(C.target_in_scope("example.com", back["scope"]))

    def test_session_roundtrip(self):
        session = {"name": "unit", "objective": "obj", "messages": [],
                   "findings": [{"category": "finding", "text": "x"}],
                   "targets": [], "credentials": [], "actions": [], "artifacts": []}
        C.save_session(session)
        back = C.load_session("unit")
        self.assertEqual(back["objective"], "obj")
        self.assertEqual(len(back["findings"]), 1)

    def test_get_token_missing_file(self):
        with self.assertRaises((FileNotFoundError, RuntimeError, KeyError)):
            C.get_token({"auth_path": "/nonexistent/auth.json", "provider": "nous"})


if __name__ == "__main__":
    unittest.main()
