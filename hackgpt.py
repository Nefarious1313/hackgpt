#!/usr/bin/env python3
"""HACKGPT — terminal red-team copilot backed by the free Nous model.

Usage:
  hackgpt "objective"                 single-shot run against an objective
  hackgpt                             interactive engagement console
  hackgpt --session client-123 "..."  named, resumable engagement

Scope: offensive tools (nmap/http/dns/subdomain) refuse targets outside the
authorized scope unless --no-scope is given. Add targets with:
  hackgpt --scope example.com --scope 10.0.0.0/24
or from the console: /scope add example.com
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.realpath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from hackgpt import config as C  # noqa: E402
from hackgpt import prompts  # noqa: E402
from hackgpt import automation, menu  # noqa: E402
from hackgpt.api import APIAuthError, APIError, NousAPI  # noqa: E402
from hackgpt.config import ScopeDenied  # noqa: E402
from hackgpt.tools import HANDLERS, TOOLS, Ctx, ToolError  # noqa: E402
from hackgpt.ui import Console  # noqa: E402

VERSION = "1.2.0"


def build_ctx(cfg: dict, session: dict, console: Console, dry_run: bool) -> Ctx:
    workdir = os.path.join(C.WORK_DIR, session["name"])
    os.makedirs(workdir, exist_ok=True)
    return Ctx(
        config=cfg,
        session=session,
        console=console,
        workdir=workdir,
        output_dir=C.OUTPUT_DIR,
        dry_run=dry_run,
    )


def _iter_json_objects(text: str):
    """Yield balanced JSON objects from prose, tolerating nested braces and strings."""
    decoder = json.JSONDecoder()
    idx = text.find("{")
    while idx != -1:
        try:
            obj, end = decoder.raw_decode(text, idx)
        except json.JSONDecodeError:
            idx = text.find("{", idx + 1)
            continue
        if isinstance(obj, dict):
            yield obj
        idx = text.find("{", end)


def _extract_json_tool_call(content: str) -> tuple[str, dict] | None:
    """Fallback for models that emit a JSON tool call in prose instead of native calling."""
    if not content:
        return None
    for obj in _iter_json_objects(content):
        name = obj.get("tool") or obj.get("name")
        if name not in HANDLERS:
            continue
        args = obj.get("arguments", obj.get("args"))
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                args = {}
        if not isinstance(args, dict):
            args = {k: v for k, v in obj.items() if k not in ("tool", "name", "arguments", "args")}
        return name, args
    return None


def run_agent(messages: list[dict], ctx: Ctx, api: NousAPI, console: Console) -> tuple[list[dict], dict | None]:
    """Tool-use loop: keep dispatching tool calls until the model answers."""
    max_iter = int(ctx.config.get("max_tool_iterations", 30))
    last: dict | None = None
    for i in range(max_iter):
        try:
            msg = api.complete(messages, TOOLS)
        except (APIAuthError, APIError) as exc:
            console.error(str(exc))
            return messages, None
        messages.append(msg)
        last = msg
        tool_calls = msg.get("tool_calls") or []
        if not tool_calls:
            fallback = _extract_json_tool_call(msg.get("content") or "")
            if fallback:
                name, fargs = fallback
                console.status(f"(prose tool-call fallback) {name}")
                msg["tool_calls"] = [{"id": f"fallback-{i}", "type": "function",
                                      "function": {"name": name, "arguments": json.dumps(fargs)}}]
                msg["content"] = None
                tool_calls = msg["tool_calls"]
            else:
                console.assistant(msg.get("content") or "(model returned no content)")
                return messages, msg

        console.status(f"[step {i + 1}/{max_iter}] {len(tool_calls)} tool call(s)")
        for tc in tool_calls:
            fn = (tc.get("function") or {}).get("name", "")
            raw = (tc.get("function") or {}).get("arguments") or "{}"
            try:
                args = json.loads(raw)
            except json.JSONDecodeError:
                args = {}
            if fn not in HANDLERS:
                result = f"tool error: unknown tool '{fn}'"
            else:
                console.status(f"{fn}: {json.dumps(args)[:180]}")
                try:
                    result = HANDLERS[fn](args, ctx)
                except ScopeDenied as exc:
                    result = f"SCOPE DENIED: {exc}"
                except ToolError as exc:
                    result = f"tool error: {exc}"
                except Exception as exc:  # noqa: BLE001
                    result = f"tool error: {type(exc).__name__}: {exc}"
            messages.append({"role": "tool", "tool_call_id": tc.get("id", ""), "content": str(result)})
            console.tool(str(result)[:600])

    console.error(f"stopped after {max_iter} tool iterations without a final answer")
    return messages, last


def run_objective(objective: str, cfg: dict, session: dict, console: Console, api: NousAPI,
                  ctx: Ctx, save_report: bool = True) -> tuple[list[dict], dict | None]:
    """Single-shot AI engagement: bootstrap, run the agent loop, persist, report."""
    session["objective"] = objective
    prompts.bootstrap_session(session)
    if not session["messages"]:
        session["messages"] = prompts.initial_messages(objective, cfg.get("scope", []))
    messages, msg = run_agent(session["messages"], ctx, api, console)
    session["messages"] = messages
    save(cfg, session, messages)
    if save_report:
        from hackgpt.report import render_markdown
        path = os.path.join(C.OUTPUT_DIR, f"report-{session['name']}.md")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(render_markdown(session, cfg))
        console.status(f"report saved -> {path}")
    return messages, msg


def save(cfg: dict, session: dict, messages: list[dict]) -> None:
    session["messages"] = messages[-400:]
    session["updated"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    C.save_session(session)
    C.save_config(cfg)


def slash_command(line: str, cfg: dict, session: dict, console: Console, state: dict) -> bool:
    """Handle a console slash command. Returns True if handled."""
    parts = line.strip().split()
    if not parts:
        return False
    cmd, rest = parts[0].lower(), parts[1:]
    if cmd in ("/exit", "/quit", "/q"):
        raise SystemExit(0)
    if cmd == "/help":
        console.assistant(
            "**Console commands**\n"
            "/scope [list|add <target>|remove <target>|check <target>] — manage authorized targets\n"
            "/note <text> — record a finding\n"
            "/report [save] — show or save the engagement report\n"
            "/model <name> — switch model for this session\n"
            "/dry-run on|off — toggle execution suppression\n"
            "/confirm on|off — confirm each shell command\n"
            "/reset — clear this session's history\n"
            "/save — persist session now\n"
            "/help, /exit"
        )
        return True
    if cmd == "/scope":
        action = rest[0] if rest else "list"
        target = rest[1] if len(rest) > 1 else ""
        return _handle_scope(action, target, cfg, session, console)
    if cmd == "/note":
        text = " ".join(rest).strip()
        if text:
            session.setdefault("findings", []).append(
                {"category": "finding", "text": text, "ts": time.strftime("%Y-%m-%dT%H:%M:%S")})
            console.status("note recorded")
        return True
    if cmd == "/report":
        from hackgpt.report import render_markdown

        if rest and rest[0] == "save":
            path = os.path.join(C.OUTPUT_DIR, f"report-{session['name']}.md")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(render_markdown(session, cfg))
            console.status(f"report saved -> {path}")
        else:
            console.assistant(render_markdown(session, cfg))
        return True
    if cmd == "/model":
        if rest:
            cfg["model"] = rest[0]
            console.status(f"model set to {rest[0]}")
        else:
            console.status(f"model: {cfg.get('model')}")
        return True
    if cmd == "/dry-run":
        state["dry_run"] = bool(rest) and rest[0].lower() in ("on", "1", "true", "yes")
        console.status(f"dry-run: {'on' if state['dry_run'] else 'off'}")
        return True
    if cmd == "/confirm":
        cfg["confirm_shell"] = bool(rest) and rest[0].lower() in ("on", "1", "true", "yes")
        console.status(f"confirm shell: {'on' if cfg['confirm_shell'] else 'off'}")
        return True
    if cmd == "/reset":
        session["messages"] = []
        console.status("session history cleared")
        return True
    if cmd == "/save":
        C.save_session(session)
        console.status("session saved")
        return True
    return False


def _handle_scope(action: str, target: str, cfg: dict, session: dict, console: Console) -> bool:
    scope = cfg.setdefault("scope", [])
    if action == "list":
        console.assistant("authorized scope:\n" + ("\n".join(
            f"  - {e if isinstance(e, str) else e.get('target')}" for e in scope) or "  (empty)"))
    elif action == "add" and target:
        scope.append({"target": target, "added": time.strftime("%Y-%m-%dT%H:%M:%S")})
        C.save_config(cfg)
        console.status(f"added to scope: {target}")
    elif action == "remove" and target:
        cfg["scope"] = [e for e in scope if (e if isinstance(e, str) else e.get("target")) != target]
        C.save_config(cfg)
        console.status(f"removed from scope: {target}")
    elif action == "check" and target:
        console.status(f"{target}: {'IN scope' if C.target_in_scope(target, scope) else 'OUT of scope'}")
    else:
        console.error("usage: /scope list|add <target>|remove <target>|check <target>")
    return True


def main() -> int:
    ap = argparse.ArgumentParser(prog="hackgpt", description="Terminal red-team copilot (Nous model).")
    ap.add_argument("objective", nargs="?", help="objective text; omit for interactive console")
    ap.add_argument("--session", default="default", help="engagement/session name")
    ap.add_argument("--model", help="override model id")
    ap.add_argument("--scope", action="append", default=[], metavar="TARGET",
                    help="seed authorized scope (repeatable)")
    ap.add_argument("--no-scope", action="store_true", help="disable scope enforcement (lab/CTF)")
    ap.add_argument("--confirm", action="store_true", help="confirm each shell command")
    ap.add_argument("--dry-run", action="store_true", help="do not execute shell/scan/listener tools")
    ap.add_argument("--max-iter", type=int, help="max tool iterations per turn")
    ap.add_argument("--reset", action="store_true", help="start with a clean session history")
    ap.add_argument("--report", action="store_true", help="save report to output/ on exit")
    ap.add_argument("--auto", metavar="TARGET", help="one-command deterministic engagement + report")
    ap.add_argument("--quick", metavar="TARGET", help="nmap top100 + web probe")
    ap.add_argument("--web", metavar="URL", help="deep web checks on a URL")
    ap.add_argument("--deep", action="store_true", help="with --auto: nmap -p- -sV")
    ap.add_argument("--research", action="store_true", help="with --auto: add a light CVE pass")
    ap.add_argument("--menu", action="store_true", help="guided menu")
    ap.add_argument("--doctor", action="store_true", help="check deps, auth, model")
    ap.add_argument("--fix", action="store_true", help="with --doctor: install what is missing")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--version", action="version", version=f"hackgpt {VERSION}")
    args = ap.parse_args()

    cfg = C.load_config()
    if args.model:
        cfg["model"] = args.model
    if args.max_iter:
        cfg["max_tool_iterations"] = args.max_iter
    if args.no_scope:
        cfg["enforce_scope"] = False
    if args.confirm:
        cfg["confirm_shell"] = True
    for t in args.scope:
        if not any((e if isinstance(e, str) else e.get("target")) == t for e in cfg.get("scope", [])):
            cfg.setdefault("scope", []).append({"target": t, "added": time.strftime("%Y-%m-%dT%H:%M:%S")})
    C.save_config(cfg)

    session = C.load_session(args.session)
    if args.reset:
        session["messages"] = []
    if args.objective:
        session["objective"] = args.objective
    prompts.bootstrap_session(session)

    console = Console(quiet=args.quiet)
    console.banner(
        f"session: {session['name']}   model: {cfg['model']}\n"
        f"scope: {', '.join((e if isinstance(e, str) else e.get('target')) for e in cfg.get('scope', [])) or '(empty)'}\n"
        f"objective: {session.get('objective') or '-'}\n"
        f"dry-run: {args.dry_run}   scope enforcement: {cfg.get('enforce_scope')}"
    )

    api = NousAPI(cfg)
    state = {"dry_run": args.dry_run}
    ctx = build_ctx(cfg, session, console, args.dry_run)

    # ---- automated / guided modes ---------------------------------------
    if args.doctor:
        return 0 if automation.doctor(cfg, fix=args.fix, console=console) else 1
    if args.auto:
        sess = C.load_session(args.session)
        prompts.bootstrap_session(sess)
        automation.auto_engagement(args.auto, cfg, sess, console, deep=args.deep,
                                   dry_run=args.dry_run, research=args.research)
        save(cfg, sess, sess.get("messages", []))
        return 0
    if args.quick:
        sess = C.load_session(args.session)
        prompts.bootstrap_session(sess)
        automation.quick_scan(args.quick, cfg, sess, console, dry_run=args.dry_run)
        save(cfg, sess, sess.get("messages", []))
        return 0
    if args.web:
        sess = C.load_session(args.session)
        prompts.bootstrap_session(sess)
        automation.web_checks(args.web, cfg, sess, console, dry_run=args.dry_run)
        save(cfg, sess, sess.get("messages", []))
        return 0
    if args.menu:
        return menu.run_menu(cfg, console, api, run_objective)

    if not session["messages"]:
        session["messages"] = prompts.initial_messages(session.get("objective") or "(interactive)", cfg.get("scope", []))

    # ---- single-shot mode ------------------------------------------------
    if args.objective:
        _, msg = run_objective(args.objective, cfg, session, console, api, ctx,
                               save_report=args.report)
        return 0 if msg else 1

    # ---- interactive console --------------------------------------------
    console.status("interactive console — type /help for commands, /exit to quit")
    console.status("tip: `hackgpt --menu` for a guided menu, `hackgpt --auto <target>` for a one-command engagement")
    while True:
        try:
            line = console.ask("hackgpt")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line.strip():
            continue
        if line.startswith("/"):
            try:
                slash_command(line, cfg, session, console, state)
            except SystemExit:
                break
            ctx.dry_run = state["dry_run"]
            continue
        if line.strip() in ("exit", "quit"):
            break
        session["messages"].append({"role": "user", "content": line})
        messages, msg = run_agent(session["messages"], ctx, api, console)
        session["messages"] = messages
        save(cfg, session, messages)
        if msg is None:
            console.error("turn failed (API error) — fix auth/model and continue")

    if args.report:
        from hackgpt.report import render_markdown
        path = os.path.join(C.OUTPUT_DIR, f"report-{session['name']}.md")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(render_markdown(session, cfg))
        console.status(f"report saved -> {path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[!] interrupted")
        raise SystemExit(130)
