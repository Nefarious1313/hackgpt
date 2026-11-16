"""Guided menu: numbered actions, minimal typing.

`hackgpt --menu` is the simple front door. Each option asks for the one or two
inputs it needs, runs the work, and saves a session + report.
"""
from __future__ import annotations

import json

from . import automation as A
from . import config as C
from . import prompts

MENU = """\
**HackGPT menu**
  - 1) Full engagement  — recon→scan→web→MITM audit→MSF runbooks→report
  - 2) Auto engagement  — one target, full pipeline, report
  - 3) Quick scan       — nmap top100 + web probe
  - 4) Web checks       — headers / methods / CORS / paths + TLS
  - 5) Research         — CVE / exploit lookup
  - 6) Utilities        — encode / hash / IP intel / TLS / dirs / MITM / MSF
  - 7) Ask the AI       — natural-language objective (agent loop)
  - 8) Doctor           — check deps, auth, model
  - 9) Help             — flags and usage
  - 10) Watch DNS       — compare scoped A/AAAA records on an interval
  - 0) Exit"""

UTIL_MENU = """\
**Utilities**
  - 1) encode / decode (base64, hex, url, rot13, jwt)
  - 2) identify a hash
  - 3) IP intel (ASN / geo)
  - 4) TLS certificate
  - 5) directory probe
  - 6) Metasploit module catalog search (search only)
  - 7) MITM resilience audit (read-only, scoped)
  - 8) msfvenom payload generation (needs msfvenom)
  - 9) MSF runbook planner (writes a reviewed .rc)
  - 10) MSF RPC status (remote msfrpcd)
  - 11) MSF RPC run module (opt-in execution)
  - 12) MSF RPC sessions (list/info/stop)
  - 0) Back"""

HELP = """\
**HackGPT usage**
  hackgpt --menu                 this menu
  hackgpt --full example.com     maximal pipeline (+ MITM audits, MSF runbooks)
  hackgpt --auto example.com     full deterministic engagement + report
  hackgpt --auto 203.0.113.0/24 --deep --research
  hackgpt --quick example.com    (same as menu option 3)
  hackgpt --web example.com      (same as menu option 4)
  hackgpt --doctor [--fix]       check / repair the environment
  hackgpt --msf-exec ...          allow Metasploit execution (scope-bound, confirmed)
  hackgpt "your objective"       AI agent loop, one shot
  hackgpt                        interactive console
  hackgpt --dry-run ...          plan without executing
Other flags: --session NAME, --scope TARGET, --no-scope, --confirm, --report,
--model ID, --reset, --version. Run `bash run_tests.sh` for the test suite."""


def _ask(console, prompt: str, required: bool = False) -> str:
    try:
        ans = (console.ask(prompt) or "").strip()
    except EOFError:
        return ""
    if required and not ans:
        console.error("a value is required")
    return ans


def _session(name: str) -> dict:
    session = C.load_session(name)
    prompts.bootstrap_session(session)
    return session


def _finish(cfg: dict, session: dict) -> None:
    C.save_session(session)
    C.save_config(cfg)


def run_menu(cfg: dict, console, api, run_objective) -> int:
    console.assistant(MENU)
    while True:
        try:
            choice = (console.ask("choice") or "").strip()
        except EOFError:
            break
        if choice in ("0", "q", "quit", "exit", ""):
            break

        if choice == "1":
            target = _ask(console, "target (domain / IP / CIDR)", required=True)
            if not target:
                continue
            deep = _ask(console, "deep scan? [y/N]").lower().startswith("y")
            execute = _ask(console, "attempt Metasploit execution? [y/N]").lower().startswith("y")
            name = _ask(console, "session name [full]") or "full"
            session = _session(name)
            A.full_engagement(target, cfg, session, console, deep=deep, msf_execute=execute)
            _finish(cfg, session)

        elif choice == "2":
            target = _ask(console, "target (domain / IP / CIDR)", required=True)
            if not target:
                continue
            deep = _ask(console, "deep scan? [y/N]").lower().startswith("y")
            name = _ask(console, "session name [auto]") or "auto"
            session = _session(name)
            A.auto_engagement(target, cfg, session, console, deep=deep)
            _finish(cfg, session)

        elif choice == "3":
            target = _ask(console, "target", required=True)
            if not target:
                continue
            name = _ask(console, "session name [quick]") or "quick"
            session = _session(name)
            A.quick_scan(target, cfg, session, console)
            _finish(cfg, session)

        elif choice == "4":
            url = _ask(console, "url", required=True)
            if not url:
                continue
            name = _ask(console, "session name [web]") or "web"
            session = _session(name)
            A.web_checks(url, cfg, session, console)
            _finish(cfg, session)

        elif choice == "5":
            query = _ask(console, "CVE id or keyword", required=True)
            if not query:
                continue
            session = _session("research")
            A.research(query, cfg, session, console)
            _finish(cfg, session)

        elif choice == "6":
            _utilities(cfg, console)

        elif choice == "7":
            objective = _ask(console, "objective", required=True)
            if not objective:
                continue
            name = _ask(console, "session name [ai]") or "ai"
            session = _session(name)
            ctx = A.make_ctx(cfg, session, console)
            run_objective(objective, cfg, session, console, api, ctx, save_report=True)
            _finish(cfg, session)

        elif choice == "8":
            A.doctor(cfg, fix=False, console=console)

        elif choice == "9":
            console.assistant(HELP)

        elif choice == "10":
            domain = _ask(console, "in-scope domain", required=True)
            if not domain:
                continue
            try:
                interval = int(_ask(console, "interval seconds [3600]") or 3600)
                count = int(_ask(console, "poll count [0 = until Ctrl-C]") or 0)
            except ValueError:
                console.error("interval and poll count must be integers")
                continue
            name = _ask(console, "session name [dns-watch]") or "dns-watch"
            session = _session(name)
            A.watch_dns(domain, cfg, session, console, interval=interval, count=count)
            _finish(cfg, session)

        else:
            console.error("choose 0-10")
    return 0


def _utilities(cfg: dict, console) -> None:
    while True:
        console.assistant(UTIL_MENU)
        try:
            choice = (console.ask("utility") or "").strip()
        except EOFError:
            break
        if choice in ("0", "q", "back", ""):
            break
        session = _session("utils")
        try:
            if choice == "1":
                out = A.utility("encode", {
                    "input": _ask(console, "input", required=True),
                    "op": _ask(console, "op (encode/decode) [encode]") or "encode",
                    "codec": _ask(console, "codec (base64/hex/url/rot13/jwt) [base64]") or "base64",
                }, cfg, session, console)
            elif choice == "2":
                out = A.utility("hash", {"hash": _ask(console, "hash", required=True)}, cfg, session, console)
            elif choice == "3":
                out = A.utility("ip", {"target": _ask(console, "IP / CIDR", required=True)}, cfg, session, console)
            elif choice == "4":
                out = A.utility("tls", {
                    "target": _ask(console, "host", required=True),
                    "port": int(_ask(console, "port [443]") or 443),
                }, cfg, session, console)
            elif choice == "5":
                out = A.utility("dirs", {"url": _ask(console, "url", required=True)}, cfg, session, console)
            elif choice == "6":
                action = _ask(console, "action (status/search) [search]") or "search"
                query = ""
                mtype = "auxiliary"
                if action == "search":
                    query = _ask(console, "module search query")
                    mtype = _ask(console, "type (auxiliary/exploit/post/payload/encoder/nops/all) [auxiliary]") or "auxiliary"
                out = A.utility("msf", {"action": action, "query": query, "type": mtype},
                                cfg, session, console)
            elif choice == "7":
                out = A.utility("mitm", {
                    "target": _ask(console, "host[:port]", required=True),
                    "port": int(_ask(console, "port [443]") or 443),
                }, cfg, session, console)
            elif choice == "8":
                fmt = _ask(console, "format (elf/exe/raw/apk/jar/psh/bash/python/...) [raw]") or "raw"
                out = A.utility("msf_payload", {
                    "payload": _ask(console, "payload (e.g. linux/x64/meterpreter/reverse_tcp)", required=True),
                    "lhost": _ask(console, "lhost", required=True),
                    "lport": _ask(console, "lport", required=True),
                    "format": fmt,
                    "output": _ask(console, "output file [default auto]"),
                }, cfg, session, console)
            elif choice == "9":
                out = A.utility("msf_plan", {
                    "module": _ask(console, "module path (e.g. exploit/multi/handler)", required=True),
                    "rhosts": _ask(console, "rhosts (in scope)", required=True),
                    "lhost": _ask(console, "lhost [optional]"),
                    "lport": _ask(console, "lport [4444]"),
                    "name": _ask(console, "runbook name [auto]"),
                }, cfg, session, console)
            elif choice == "10":
                out = A.utility("rpc_status", {}, cfg, session, console)
            elif choice == "11":
                raw_opts = _ask(console, 'options JSON ({"RHOSTS":"10.0.0.5","LHOST":"..."})') or "{}"
                try:
                    opts = json.loads(raw_opts)
                except ValueError as exc:
                    console.error(f"invalid options JSON: {exc}")
                    continue
                out = A.utility("rpc_run", {
                    "type": _ask(console, "type (exploit/auxiliary/post/payload) [exploit]") or "exploit",
                    "module": _ask(console, "module", required=True),
                    "options": opts,
                }, cfg, session, console)
            elif choice == "12":
                action = _ask(console, "action (list/info/stop) [list]") or "list"
                sid = "" if action == "list" else _ask(console, "sid", required=True)
                out = A.utility("rpc_session", {"action": action, "sid": sid}, cfg, session, console)
            else:
                console.error("choose 0-12")
                continue
            console.assistant(out)
        except Exception as exc:  # noqa: BLE001
            console.error(f"utility failed: {exc}")
        _finish(cfg, session)
