"""Agent loop: prose JSON fallback, tool dispatch, session truncation."""
from __future__ import annotations

import importlib.util
import json
import os
import unittest

from hackgpt import config as C

from .helpers import FakeConsole, make_ctx

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("hackgpt_cli", os.path.join(ROOT, "hackgpt.py"))
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)


class ProseFallback(unittest.TestCase):
    def test_object_args(self):
        content = 'Sure: {"tool": "note", "arguments": {"text": "hi"}}'
        name, args = cli._extract_json_tool_call(content)
        self.assertEqual(name, "note")
        self.assertEqual(args, {"text": "hi"})

    def test_string_args(self):
        content = '{"name": "shell", "args": "{\\"command\\": \\"id\\"}"}'
        name, args = cli._extract_json_tool_call(content)
        self.assertEqual(name, "shell")
        self.assertEqual(args, {"command": "id"})

    def test_flat_args(self):
        content = '{"tool": "note", "text": "flat"}'
        name, args = cli._extract_json_tool_call(content)
        self.assertEqual(name, "note")
        self.assertEqual(args.get("text"), "flat")

    def test_unknown_tool_ignored(self):
        self.assertIsNone(cli._extract_json_tool_call('{"tool": "nope", "x": 1}'))

    def test_non_json_ignored(self):
        self.assertIsNone(cli._extract_json_tool_call("no tool call here"))

    def test_empty(self):
        self.assertIsNone(cli._extract_json_tool_call(""))


class FakeAPI:
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = 0

    def complete(self, messages, tools=None, tool_choice="auto"):
        self.calls += 1
        return self.replies.pop(0)


class AgentLoop(unittest.TestCase):
    def test_dispatches_tool_then_answers(self):
        ctx = make_ctx()
        replies = [
            {"role": "assistant", "content": None, "tool_calls": [
                {"id": "c1", "type": "function",
                 "function": {"name": "note", "arguments": json.dumps({"text": "via loop"})}}]},
            {"role": "assistant", "content": "done", "tool_calls": []},
        ]
        api = FakeAPI(replies)
        messages, msg = cli.run_agent([{"role": "user", "content": "go"}], ctx, api, ctx.console)
        self.assertEqual(msg["content"], "done")
        self.assertEqual(api.calls, 2)
        self.assertEqual(ctx.session["findings"][0]["text"], "via loop")
        tools = [m for m in messages if m.get("role") == "tool"]
        self.assertEqual(len(tools), 1)

    def test_prose_fallback_executes(self):
        ctx = make_ctx()
        replies = [
            {"role": "assistant", "content": 'ok {"tool": "note", "arguments": {"text": "prose"}}',
             "tool_calls": []},
            {"role": "assistant", "content": "finished", "tool_calls": []},
        ]
        api = FakeAPI(replies)
        _, msg = cli.run_agent([{"role": "user", "content": "go"}], ctx, api, ctx.console)
        self.assertEqual(msg["content"], "finished")
        self.assertEqual(ctx.session["findings"][0]["text"], "prose")

    def test_unknown_tool_is_reported(self):
        ctx = make_ctx()
        replies = [
            {"role": "assistant", "content": None, "tool_calls": [
                {"id": "c1", "type": "function",
                 "function": {"name": "does_not_exist", "arguments": "{}"}}]},
            {"role": "assistant", "content": "stopped", "tool_calls": []},
        ]
        _, msg = cli.run_agent([{"role": "user", "content": "go"}], ctx, FakeAPI(replies),
                               ctx.console)
        self.assertEqual(msg["content"], "stopped")
        self.assertIn("unknown tool", ctx.console.output[-2] if len(ctx.console.output) > 1 else "")

    def test_scope_denial_is_fed_back(self):
        ctx = make_ctx(scope=[])
        replies = [
            {"role": "assistant", "content": None, "tool_calls": [
                {"id": "c1", "type": "function",
                 "function": {"name": "nmap_scan", "arguments": json.dumps({"target": "10.1.1.1"})}}]},
            {"role": "assistant", "content": "cannot", "tool_calls": []},
        ]
        _, msg = cli.run_agent([{"role": "user", "content": "go"}], ctx, FakeAPI(replies),
                               ctx.console)
        self.assertEqual(msg["content"], "cannot")
        self.assertTrue(any("SCOPE DENIED" in str(o) for o in ctx.console.output))


class SaveAndCtx(unittest.TestCase):
    def test_build_ctx_creates_workdir(self):
        cfg = {"scope": []}
        session = {"name": "unit", "messages": [], "findings": [], "targets": [],
                   "credentials": [], "actions": [], "artifacts": []}
        ctx = cli.build_ctx(cfg, session, FakeConsole(), False)
        self.assertTrue(os.path.isdir(ctx.workdir))

    def test_save_truncates_to_400(self):
        cfg = {"scope": []}
        session = {"name": "trunc", "messages": [{"i": i} for i in range(500)],
                   "findings": [], "targets": [], "credentials": [], "actions": [],
                   "artifacts": []}
        cli.save(cfg, session, session["messages"])
        back = C.load_session("trunc")
        self.assertEqual(len(back["messages"]), 400)
        self.assertEqual(back["messages"][-1], {"i": 499})


if __name__ == "__main__":
    unittest.main()
