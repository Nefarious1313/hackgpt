"""MSFRPCD client: MessagePack codec vectors, transport flow (mocked), handler gates."""
from __future__ import annotations

import unittest
from typing import cast
from unittest.mock import patch

from hackgpt.config import ScopeDenied
from hackgpt.msfrpc import MsfRpcClient, RpcError, pack, unpack
from hackgpt.tools import (
    ToolError,
    h_msf_rpc_console,
    h_msf_rpc_run,
    h_msf_rpc_session,
    h_msf_rpc_status,
)

from .helpers import make_ctx


class _Resp:
    def __init__(self, payload: bytes):
        self._payload = payload

    def read(self) -> bytes:
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _standard_handler(method, params):
    if method == "auth.login":
        return {"token": "tok123"}
    if method == "core.version":
        return {"version": "6.3.42", "ruby": "3.0.2", "platform": "x86_64-linux"}
    if method == "console.create":
        return {"id": "c1"}
    if method == "console.write":
        return {"prompt": "msf6 > ", "busy": False}
    if method == "console.read":
        return {"data": "Sessions\n=======\n\nId  Name\n--  ----\n",
                "prompt": "msf6 > ", "busy": False}
    if method == "module.execute":
        return {"job_id": 3, "uuid": "abc123"}
    if method == "session.list":
        return {"1": {"type": "shell", "username": "root", "session_host": "10.0.0.5",
                      "session_port": 4444, "via_exploit": "exploit/linux/local/x"}}
    if method == "session.stop":
        return True
    return {}


def _fake_urlopen(handler):
    def urlopen(req, timeout=None):
        body = unpack(req.data)
        if not isinstance(body, dict):
            body = {}
        return _Resp(pack({"result": handler(str(body.get("method") or ""), body.get("params") or [])}))

    return urlopen


def _rpc_cfg(**over):
    cfg = {"enforce_scope": True, "scope": [{"target": "127.0.0.1", "added": "t"}],
           "timeout_default": 5, "user_agent": "hackgpt-test",
           "msfrpcd_host": "127.0.0.1", "msfrpcd_port": 55553,
           "msfrpcd_user": "msf", "msfrpcd_pass": "secret", "msfrpcd_ssl": False}
    cfg.update(over)
    return cfg


def _ctx(**over):
    dry = bool(over.pop("dry_run", False))
    ctx = make_ctx(scope=["127.0.0.1"], dry_run=dry)
    ctx.config.update(_rpc_cfg(**over))
    return ctx


class Codec(unittest.TestCase):
    def test_known_vectors(self):
        self.assertEqual(pack(None), b"\xc0")
        self.assertEqual(pack(True), b"\xc3")
        self.assertEqual(pack(False), b"\xc2")
        self.assertEqual(pack(1), b"\x01")
        self.assertEqual(pack(-1), b"\xff")
        self.assertEqual(pack("hi"), b"\xa2hi")
        self.assertEqual(pack({}), b"\x80")
        self.assertEqual(pack([]), b"\x90")
        self.assertEqual(pack([1, 2]), b"\x92\x01\x02")
        self.assertEqual(pack({"a": 1}), b"\x81\xa1a\x01")

    def test_roundtrip_nested(self):
        obj = {"version": "1.0", "method": "module.execute",
               "params": ["exploit", "linux/http/x",
                          {"RHOSTS": "10.0.0.5", "LPORT": 4444, "SSL": True}],
               "meta": [None, -5, 3.5]}
        self.assertEqual(unpack(pack(obj)), obj)

    def test_unpack_known_bytes(self):
        self.assertEqual(unpack(b"\x81\xa1a\x01"), {"a": 1})
        self.assertEqual(unpack(b"\x92\x01\x02"), [1, 2])
        self.assertEqual(unpack(b"\xa2hi"), "hi")


class ClientFlow(unittest.TestCase):
    def test_login_and_version(self):
        seen_headers = []

        def urlopen(req, timeout=None):
            seen_headers.append(dict(req.headers))
            return _fake_urlopen(_standard_handler)(req, timeout)

        with patch("urllib.request.urlopen", side_effect=urlopen):
            cli = MsfRpcClient(_rpc_cfg())
            token = cli.login()
            ver = cast(dict, cli.version())
        self.assertEqual(token, "tok123")
        self.assertEqual(ver["version"], "6.3.42")
        auth = seen_headers[1].get("Authorization") or seen_headers[1].get("authorization")
        self.assertEqual(auth, "Bearer tok123")

    def test_error_response_raises(self):
        def urlopen(req, timeout=None):
            return _Resp(pack({"error": "unauthenticated"}))

        with patch("urllib.request.urlopen", side_effect=urlopen):
            cli = MsfRpcClient(_rpc_cfg())
            with self.assertRaises(RpcError):
                cli.call("core.version")

    def test_transport_failure_raises(self):
        def urlopen(req, timeout=None):
            raise OSError("connection refused")

        with patch("urllib.request.urlopen", side_effect=urlopen):
            cli = MsfRpcClient(_rpc_cfg())
            with self.assertRaises(RpcError):
                cli.login()

    def test_console_flow(self):
        calls = []

        def handler(method, params):
            calls.append(method)
            return _standard_handler(method, params)

        with patch("urllib.request.urlopen", side_effect=_fake_urlopen(handler)):
            cli = MsfRpcClient(_rpc_cfg())
            cid = cast(dict, cli.console_create())["id"]
            cli.console_write(cid, "sessions\n")
            data = cast(dict, cli.console_read(cid))["data"]
        self.assertEqual(cid, "c1")
        self.assertIn("Id  Name", data)
        self.assertEqual(calls, ["auth.login", "console.create", "console.write", "console.read"])

    def test_module_execute_params(self):
        captured = {}

        def handler(method, params):
            if method == "module.execute":
                captured.update(params[2])
            return _standard_handler(method, params)

        with patch("urllib.request.urlopen", side_effect=_fake_urlopen(handler)):
            cli = MsfRpcClient(_rpc_cfg())
            res = cast(dict, cli.module_execute("exploit", "linux/http/x", {"RHOSTS": "10.0.0.5"}))
        self.assertEqual(captured["RHOSTS"], "10.0.0.5")
        self.assertEqual(res["job_id"], 3)


class RpcHandlers(unittest.TestCase):
    def test_status_requires_host(self):
        ctx = make_ctx()
        with self.assertRaises(ToolError):
            h_msf_rpc_status({}, ctx)

    def test_status_renders_version(self):
        ctx = _ctx()
        with patch("urllib.request.urlopen", side_effect=_fake_urlopen(_standard_handler)):
            out = h_msf_rpc_status({}, ctx)
        self.assertIn("msf_rpc connected", out)
        self.assertIn("6.3.42", out)
        self.assertEqual(ctx.session["actions"][-1]["tool"], "msf_rpc_status")

    def test_run_gated_by_msf_execute(self):
        ctx = _ctx()
        with self.assertRaises(ToolError) as cm:
            h_msf_rpc_run({"type": "exploit", "module": "linux/http/x"}, ctx)
        self.assertIn("enabled", str(cm.exception))

    def test_run_out_of_scope_rhosts(self):
        ctx = _ctx(msf_execute=True)
        ctx.config["scope"] = []
        with self.assertRaises(ScopeDenied):
            h_msf_rpc_run({"type": "exploit", "module": "linux/http/x",
                           "options": {"RHOSTS": "10.1.1.1"}}, ctx)

    def test_run_dry_run_preview(self):
        ctx = _ctx(msf_execute=True, dry_run=True)
        out = h_msf_rpc_run({"type": "exploit", "module": "linux/http/x",
                             "options": {"RHOSTS": "127.0.0.1"}}, ctx)
        self.assertIn("[dry-run] would run via RPC", out)

    def test_run_executes_with_mock(self):
        ctx = _ctx(msf_execute=True)
        with patch("urllib.request.urlopen", side_effect=_fake_urlopen(_standard_handler)):
            out = h_msf_rpc_run({"type": "exploit", "module": "linux/http/x",
                                 "options": {"RHOSTS": "127.0.0.1"}}, ctx)
        self.assertIn("launched via remote MSF", out)
        self.assertIn("job_id: 3", out)
        self.assertEqual(ctx.session["actions"][-1]["tool"], "msf_rpc_run")

    def test_run_bad_type(self):
        with self.assertRaises(ToolError):
            h_msf_rpc_run({"type": "nope", "module": "x/y"}, _ctx(msf_execute=True))

    def test_session_list_renders(self):
        ctx = _ctx()
        with patch("urllib.request.urlopen", side_effect=_fake_urlopen(_standard_handler)):
            out = h_msf_rpc_session({"action": "list"}, ctx)
        self.assertIn("shell", out)
        self.assertIn("10.0.0.5", out)

    def test_console_write_gated(self):
        ctx = _ctx()
        with self.assertRaises(ToolError):
            h_msf_rpc_console({"action": "write", "cid": "c1", "data": "sessions"}, ctx)

    def test_console_create_stores_cid(self):
        ctx = _ctx()
        with patch("urllib.request.urlopen", side_effect=_fake_urlopen(_standard_handler)):
            out = h_msf_rpc_console({"action": "create"}, ctx)
        self.assertIn("console created: c1", out)
        self.assertIn("c1", ctx.session.get("rpc_consoles", {}))


if __name__ == "__main__":
    unittest.main()
