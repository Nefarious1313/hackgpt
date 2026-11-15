"""Guided menu: numbered actions, minimal typing.

`hackgpt --menu` is the simple front door. Each option asks for the one or two
inputs it needs, runs the work, and saves a session + report.
"""
from __future__ import annotations

from . import automation as A
from . import config as C
from . import prompts

MENU = """\
**HackGPT menu**
  - 1) Auto engagement  — one target, full pipeline, report
  - 2) Quick scan       — nmap top100 + web probe
  - 3) Web checks       — headers / methods / CORS / paths + TLS
  - 4) Research         — CVE / exploit lookup
  - 5) Utilities        — encode / hash / IP intel / TLS / dirs
  - 6) Ask the AI       — natural-language objective (agent loop)
  - 7) Doctor           — check deps, auth, model
  - 8) Help             — flags and usage
  - 0) Exit"""

UTIL_MENU = """\
**Utilities**
  - 1) encode / decode (base64, hex, url, rot13, jwt)
  - 2) identify a hash
  - 3) IP intel (ASN / geo)
  - 4) TLS certificate
  - 5) directory probe
  - 0) Back"""

HELP = """\
**HackGPT usage**
  hackgpt --menu                 this menu
  hackgpt --auto example.com     full deterministic engagement + report
  hackgpt --auto 203.0.113.0/24 --deep --research
  hackgpt --quick example.com    (same as menu option 2)
  hackgpt --web example.com      (same as menu option 3)
  hackgpt --doctor [--fix]       check / repair the environment
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
            name = _ask(console, "session name [auto]") or "auto"
            session = _session(name)
            A.auto_engagement(target, cfg, session, console, deep=deep)
            _finish(cfg, session)

        elif choice == "2":
            target = _ask(console, "target", required=True)
            if not target:
                continue
            name = _ask(console, "session name [quick]") or "quick"
            session = _session(name)
            A.quick_scan(target, cfg, session, console)
            _finish(cfg, session)

        elif choice == "3":
            url = _ask(console, "url", required=True)
            if not url:
                continue
            name = _ask(console, "session name [web]") or "web"
            session = _session(name)
            A.web_checks(url, cfg, session, console)
            _finish(cfg, session)

        elif choice == "4":
            query = _ask(console, "CVE id or keyword", required=True)
            if not query:
                continue
            session = _session("research")
            A.research(query, cfg, session, console)
            _finish(cfg, session)

        elif choice == "5":
            _utilities(cfg, console)

        elif choice == "6":
            objective = _ask(console, "objective", required=True)
            if not objective:
                continue
            name = _ask(console, "session name [ai]") or "ai"
            session = _session(name)
            ctx = A.make_ctx(cfg, session, console)
            run_objective(objective, cfg, session, console, api, ctx, save_report=True)
            _finish(cfg, session)

        elif choice == "7":
            A.doctor(cfg, fix=False, console=console)

        elif choice == "8":
            console.assistant(HELP)

        else:
            console.error("choose 0-8")
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
            else:
                console.error("choose 0-5")
                continue
            console.assistant(out)
        except Exception as exc:  # noqa: BLE001
            console.error(f"utility failed: {exc}")
        _finish(cfg, session)
