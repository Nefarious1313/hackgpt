"""One-command automation: environment doctor + deterministic engagements.

The agent loop is flexible but needs an objective and a live model. This module is
the zero-input path: point it at a target and it runs the whole toolchain
(recon -> scan -> web -> report) deterministically, then prints a short summary.
No model calls, so it works even while the Nous free tier is at capacity.
"""
from __future__ import annotations

import ipaddress
import os
import re
import subprocess
import sys
import time
import typing as t

from . import config as C
from .tools import (
    Ctx,
    h_cve_lookup,
    h_dns_recon,
    h_dns_snapshot,
    h_encode,
    h_exploit_search,
    h_hash_info,
    h_http_probe,
    h_ip_info,
    h_mitm_audit,
    h_msf_catalog,
    h_msf_exec,
    h_msf_payload,
    h_msf_plan,
    h_msf_rpc_console,
    h_msf_rpc_run,
    h_msf_rpc_session,
    h_msf_rpc_status,
    h_nmap,
    h_note,
    h_report,
    h_subdomain_enum,
    h_tls_cert,
    h_web_dirs,
    h_web_vuln_scan,
)

WEB_PORTS = {80, 443, 8000, 8080, 8443, 8888, 3000, 5000, 9000}
PY_MODULES = {"requests": "requests", "httpx": "httpx", "yaml": "pyyaml"}
CORE_BINARIES = ["nmap", "ncat", "curl", "openssl"]
OPTIONAL_BINARIES = ["dig", "whois", "msfconsole", "msfvenom"]


def _ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _say(console: t.Any, msg: str) -> None:
    if console is not None:
        console.status(msg)
    else:
        print(f"[*] {msg}")


def _run(cmd: list[str], timeout: int = 60) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as exc:  # noqa: BLE001
        return 127, str(exc)


def make_ctx(cfg: dict, session: dict, console: t.Any, dry_run: bool = False) -> Ctx:
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


# --------------------------------------------------------------------------
# doctor
# --------------------------------------------------------------------------

def doctor(cfg: dict, fix: bool = False, console: t.Any = None) -> bool:
    """Check the environment; optionally install what is missing. True if usable."""
    rows: list[tuple[str, str, bool]] = []
    ok = True

    rows.append(("python", sys.version.split()[0], True))

    missing_py: list[str] = []
    for mod, pkg in PY_MODULES.items():
        try:
            __import__(mod)
            rows.append((f"module {mod}", "ok", True))
        except Exception:  # noqa: BLE001
            missing_py.append(pkg)
            rows.append((f"module {mod}", "MISSING", False))
            ok = False
    try:
        __import__("rich")
        rows.append(("module rich (optional)", "ok", True))
    except Exception:  # noqa: BLE001
        rows.append(("module rich (optional)", "absent (plain output)", True))

    missing_bin: list[str] = []
    for b in CORE_BINARIES:
        path = C.which(b)
        rows.append((f"binary {b}", path or "MISSING", bool(path)))
        if not path:
            missing_bin.append(b)
            ok = False
    for b in OPTIONAL_BINARIES:
        path = C.which(b)
        rows.append((f"binary {b} (optional)", path or "absent", True))

    try:
        C.get_token(cfg)
        rows.append(("nous token", "present", True))
    except Exception as exc:  # noqa: BLE001
        rows.append(("nous token", f"MISSING ({type(exc).__name__})", False))
        ok = False

    rows.append(("model", str(cfg.get("model")), True))
    rows.append(("base_url", str(cfg.get("base_url")), True))
    rows.append(("scope enforcement", str(cfg.get("enforce_scope")), True))
    rows.append(("msf execution", "enabled" if cfg.get("msf_execute") else "disabled (opt-in)", True))
    rows.append(("msf rpc host", str(cfg.get("msfrpcd_host") or "not configured"), True))

    for name, val, good in rows:
        line = f"{'OK ' if good else '!! '} {name}: {val}"
        if console is not None:
            console.status(line)
        else:
            print(line)

    if fix and (missing_py or missing_bin):
        _install(missing_py, missing_bin, console)
    elif not ok:
        _say(console, "run `hackgpt --doctor --fix` to install what is missing")
    return ok


def _install(packages: list[str], binaries: list[str], console: t.Any) -> None:
    if packages:
        _say(console, f"installing python packages: {', '.join(packages)}")
        rc, out = _run([sys.executable, "-m", "pip", "install", "-q", *packages], timeout=300)
        _say(console, "pip install finished" if rc == 0 else f"pip install failed: {out[-400:]}")
    if binaries:
        _say(console, f"installing termux packages: {', '.join(binaries)}")
        rc, out = _run(["pkg", "install", "-y", *binaries], timeout=900)
        _say(console, "pkg install finished" if rc == 0 else f"pkg install failed: {out[-400:]}")


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _seed_scope(cfg: dict, target: str) -> None:
    scope = cfg.setdefault("scope", [])
    if not any((e if isinstance(e, str) else e.get("target")) == target for e in scope):
        scope.append({"target": target, "added": _ts()})
        C.save_config(cfg)


def _is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(C.normalize_target(target))
        return True
    except ValueError:
        return False


def _live(http_out: str) -> bool:
    return bool(re.search(r"->\s*\d{3}", http_out or ""))


def _open_ports(ctx: Ctx) -> list[dict]:
    ports: list[dict] = []
    for entry in ctx.session.get("targets", []):
        ports.extend(entry.get("open_ports", []))
    return ports


def _subdomain_count(ctx: Ctx) -> int:
    for entry in ctx.session.get("targets", []):
        if "subdomains" in entry:
            return len(entry["subdomains"])
    return 0


# --------------------------------------------------------------------------
# engagements
# --------------------------------------------------------------------------

def auto_engagement(target: str, cfg: dict, session: dict, console: t.Any,
                    deep: bool = False, dry_run: bool = False,
                    research: bool = False, mitm: bool = False, msf: bool = False,
                    msf_execute: bool = False) -> dict:
    """Deterministic pipeline: recon -> scan -> web -> (MITM audit) -> (research/MSF) -> report.

    `mitm`/`msf` add capability phases. `msf_execute` lets this run execute the
    generated runbooks without persisting the flag; scope and confirmation are
    still enforced by h_msf_exec itself.
    """
    target = C.normalize_target(str(target).strip()) or str(target).strip()
    _seed_scope(cfg, target)
    run_cfg = dict(cfg, msf_execute=True) if msf_execute and not cfg.get("msf_execute") else cfg
    ctx = make_ctx(run_cfg, session, console, dry_run)
    console.banner(
        f"auto engagement: {target}\n"
        f"session: {session['name']}   profile: {'deep (nmap -p- -sV)' if deep else 'standard (nmap --top-ports 100)'}\n"
        f"dry-run: {dry_run}   scope enforcement: {cfg.get('enforce_scope')}"
        f"{'   mitm audits: on' if mitm else ''}{'   msf planning: on' if msf else ''}"
    )
    summary = {"target": target, "subdomains": 0, "open_ports": [], "web": [],
               "findings": 0, "mitm": [], "msf": []}

    # 1 -- recon
    _say(console, "[1/5] recon")
    if _is_ip(target):
        console.tool(h_ip_info({"target": target}, ctx)[:900])
    else:
        console.tool(h_dns_recon({"domain": target}, ctx)[:900])
        console.tool(h_dns_snapshot({"domain": target}, ctx)[:700])
        console.tool(h_subdomain_enum({"domain": target}, ctx)[:900])
        summary["subdomains"] = _subdomain_count(ctx)

    # 2 -- port scan
    _say(console, "[2/5] port scan")
    profile = "full" if deep else "top100"
    console.tool(h_nmap({"target": target, "profile": profile}, ctx)[:1200])
    open_ports = _open_ports(ctx)
    summary["open_ports"] = open_ports
    if open_ports:
        h_note({"text": f"nmap {profile} on {target}: "
                         + ", ".join(str(p["port"]) for p in open_ports[:25]),
                "category": "target", "host": target}, ctx)

    # 3 -- web
    _say(console, "[3/5] web checks")
    urls = [f"http://{target}", f"https://{target}"]
    for p in open_ports:
        try:
            port = int(str(p["port"]).split("/")[0])
        except (ValueError, KeyError):
            continue
        if port in WEB_PORTS and port not in (80, 443):
            urls += [f"http://{target}:{port}", f"https://{target}:{port}"]
    seen: set[str] = set()
    live: list[str] = []
    for url in urls:
        if url in seen:
            continue
        seen.add(url)
        out = h_http_probe({"url": url, "timeout": 10}, ctx)
        if _live(out):
            live.append(url)
            console.tool(f"{url} -> live")
        else:
            console.tool(f"{url} -> no response")
    for url in live:
        vuln = h_web_vuln_scan({"url": url, "timeout": 10}, ctx)
        console.tool(vuln[:800])
        hdr = next((ln for ln in vuln.splitlines() if "missing security headers" in ln), "")
        if hdr:
            h_note({"text": f"{url}: {hdr}", "category": "finding", "host": target}, ctx)
        console.tool(h_web_dirs({"url": url, "limit": 40, "timeout": 6}, ctx)[:600])
        if url.startswith("https://"):
            console.tool(h_tls_cert({"target": url.split("://", 1)[1], "timeout": 10}, ctx)[:400])
    summary["web"] = live
    if live:
        h_note({"text": f"live web endpoints: {', '.join(live)}", "category": "finding", "host": target}, ctx)

    # 3b -- MITM resilience audits (read-only posture checks)
    if mitm:
        audits = [u.split("://", 1)[1] for u in live if u.startswith("https://")]
        summary["mitm"] = audits
        if audits:
            _say(console, "[3/5] MITM resilience audits")
            for netloc in audits:
                console.tool(h_mitm_audit({"target": netloc}, ctx)[:900])
        else:
            _say(console, "[3/5] MITM resilience audits (no live HTTPS endpoints)")

    # 4 -- research (+ MSF runbook planning when requested)
    if research or msf:
        if open_ports:
            _say(console, "[4/5] research")
            seen_services: set[str] = set()
            for p in open_ports:
                name = (p.get("service") or "").strip()
                if not name or name in seen_services:
                    continue
                seen_services.add(name)
                if len(seen_services) > 3:
                    break
                console.tool(h_cve_lookup({"query": name}, ctx)[:500])
            if msf:
                summary["msf"] = _auto_msf(ctx, target, open_ports, console)
        else:
            _say(console, "[4/5] research/MSF (no open ports — nothing to do)")
    else:
        _say(console, "[4/5] research/MSF (disabled)")

    # 5 -- report
    _say(console, "[5/5] report")
    h_report({"action": "save"}, ctx)
    summary["findings"] = len(session.get("findings", []))
    _print_summary(console, summary, session)
    return summary


def _auto_msf(ctx: Ctx, target: str, open_ports: list[dict], console: t.Any) -> list[str]:
    """Search the local catalog per service and write ready-to-review runbooks.

    Execution stays opt-in: when msf_execute is enabled, each generated runbook is
    also executed (msf_exec re-checks scope and confirmation itself).
    """
    artifacts: list[str] = []
    if ctx.dry_run:
        console.tool("msf: [dry-run] would search the catalog per service and write runbooks")
        return artifacts
    has_msf = bool(C.which(ctx.config.get("msfconsole", "msfconsole")))
    if not has_msf:
        console.tool("msf: msfconsole not installed locally — using the offline module catalog; "
                     "runbooks will be written without module verification "
                     "(install MSF or point config 'msfconsole' at it to verify)")
    seen: set[str] = set()
    for p in open_ports:
        svc = (p.get("service") or "").strip()
        if not svc or svc in seen:
            continue
        seen.add(svc)
        if len(seen) > 3:
            break
        try:
            res = h_msf_catalog({"action": "search", "query": svc,
                                 "type": "exploit" if has_msf else "auxiliary"}, ctx)
        except Exception as exc:  # noqa: BLE001
            console.tool(f"msf: catalog search failed for '{svc}': {exc}")
            continue
        module = ""
        # search prints a ranked table: "  1  exploit/linux/http/foo  2024-..  normal ..."
        m = re.search(r"(?m)^\s*\d+\s+((?:auxiliary|exploit|post|payload|encoder|nops)/[A-Za-z0-9_/.\-]+)", res)
        if m:
            module = m.group(1)
        else:
            m = re.search(r"\b((?:auxiliary|exploit|post|payload|encoder|nops)/[A-Za-z0-9_/.\-]+)\b", res)
            if m:
                module = m.group(1)
        if not module:
            console.tool(f"msf: no local exploit module matched '{svc}'")
            continue
        name = re.sub(r"[^A-Za-z0-9_.\-]", "_", svc) or "svc"
        out = h_msf_plan({"module": module, "rhosts": target, "name": f"auto-{name}"}, ctx)
        console.tool(out[:700])
        path = os.path.join(C.OUTPUT_DIR, f"msf-auto-{name}.rc")
        if os.path.exists(path):
            artifacts.append(path)
        if ctx.config.get("msf_execute"):
            try:
                console.tool(h_msf_exec({"rc": path, "timeout": 300}, ctx)[:900])
            except Exception as exc:  # noqa: BLE001
                console.tool(f"msf: execution skipped: {exc}")
    return artifacts


def full_engagement(target: str, cfg: dict, session: dict, console: t.Any,
                    deep: bool = False, dry_run: bool = False,
                    msf_execute: bool = False) -> dict:
    """Maximal one-command pipeline: recon -> scan -> web -> MITM audit -> MSF runbooks -> report."""
    console.banner(
        f"full engagement: {target}\n"
        f"includes: MITM-resilience audits + Metasploit runbook planning\n"
        f"session: {session['name']}   dry-run: {dry_run}"
        f"   msf exec: {bool(msf_execute or cfg.get('msf_execute'))}"
    )
    return auto_engagement(target, cfg, session, console, deep=deep, dry_run=dry_run,
                           research=True, mitm=True, msf=True, msf_execute=msf_execute)


def quick_scan(target: str, cfg: dict, session: dict, console: t.Any,
               dry_run: bool = False) -> dict:
    """Fast path: nmap top100 + a web probe."""
    target = C.normalize_target(str(target).strip()) or str(target).strip()
    _seed_scope(cfg, target)
    ctx = make_ctx(cfg, session, console, dry_run)
    console.banner(f"quick scan: {target}")
    out = h_nmap({"target": target, "profile": "top100"}, ctx)
    console.tool(out[:1200])
    probe = h_http_probe({"url": target, "timeout": 10}, ctx)
    console.tool(probe[:500])
    h_report({"action": "save"}, ctx)
    return {"target": target, "open_ports": _open_ports(ctx), "web": _live(probe)}


def web_checks(url: str, cfg: dict, session: dict, console: t.Any,
               dry_run: bool = False) -> dict:
    """Deep web pass: probe, vuln scan, directory probe, TLS cert."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    host = C.normalize_target(url)
    _seed_scope(cfg, host)
    ctx = make_ctx(cfg, session, console, dry_run)
    console.banner(f"web checks: {url}")
    console.tool(h_http_probe({"url": url, "timeout": 10}, ctx)[:600])
    console.tool(h_web_vuln_scan({"url": url, "timeout": 10}, ctx)[:900])
    console.tool(h_web_dirs({"url": url, "limit": 60, "timeout": 6}, ctx)[:700])
    if url.startswith("https://"):
        console.tool(h_tls_cert({"target": host, "timeout": 10}, ctx)[:500])
    h_report({"action": "save"}, ctx)
    return {"url": url}


def watch_dns(domain: str, cfg: dict, session: dict, console: t.Any,
             interval: int = 3600, count: int = 0, dry_run: bool = False) -> dict:
    """Poll a scoped domain's A/AAAA baseline. count=0 runs until interrupted."""
    domain = C.normalize_target(str(domain).strip()) or str(domain).strip()
    if interval < 1:
        raise ValueError("interval must be at least 1 second")
    if count < 0:
        raise ValueError("count cannot be negative")
    _seed_scope(cfg, domain)
    ctx = make_ctx(cfg, session, console, dry_run)
    polls = 0
    try:
        while count == 0 or polls < count:
            result = h_dns_snapshot({"domain": domain}, ctx)
            console.tool(result)
            polls += 1
            if count == 0 or polls < count:
                time.sleep(interval)
    except KeyboardInterrupt:
        _say(console, "DNS watch stopped by operator")
    h_report({"action": "save"}, ctx)
    return {"domain": domain, "polls": polls, "report": os.path.join(C.OUTPUT_DIR, "report-" + session["name"] + ".md")}


def research(query: str, cfg: dict, session: dict, console: t.Any) -> dict:
    """CVE + exploit research (no remote target, no scope needed)."""
    ctx = make_ctx(cfg, session, console, False)
    console.banner(f"research: {query}")
    console.tool(h_cve_lookup({"query": query}, ctx)[:1200])
    console.tool(h_exploit_search({"query": query}, ctx)[:1200])
    return {"query": query}


def utility(kind: str, args: dict, cfg: dict, session: dict, console: t.Any) -> str:
    """Expose the local utilities to the menu."""
    ctx = make_ctx(cfg, session, console, False)
    if kind == "encode":
        return h_encode(args, ctx)
    if kind == "hash":
        return h_hash_info(args, ctx)
    if kind == "ip":
        target = str(args.get("target", "")).strip()
        if target:
            _seed_scope(cfg, target)
        return h_ip_info(args, ctx)
    if kind == "tls":
        target = str(args.get("target", "")).strip()
        if target:
            _seed_scope(cfg, target)
        return h_tls_cert(args, ctx)
    if kind == "dirs":
        return h_web_dirs(args, ctx)
    if kind == "msf":
        return h_msf_catalog(args, ctx)
    if kind == "mitm":
        target = str(args.get("target", "")).strip()
        if target:
            _seed_scope(cfg, target)
        return h_mitm_audit(args, ctx)
    if kind == "msf_payload":
        return h_msf_payload(args, ctx)
    if kind == "msf_plan":
        return h_msf_plan(args, ctx)
    if kind == "msf_exec":
        return h_msf_exec(args, ctx)
    if kind == "rpc_status":
        return h_msf_rpc_status(args, ctx)
    if kind == "rpc_console":
        return h_msf_rpc_console(args, ctx)
    if kind == "rpc_run":
        return h_msf_rpc_run(args, ctx)
    if kind == "rpc_session":
        return h_msf_rpc_session(args, ctx)
    raise ValueError(f"unknown utility '{kind}'")


def _print_summary(console: t.Any, summary: dict, session: dict) -> None:
    ports = ", ".join(str(p["port"]) for p in summary["open_ports"][:20]) or "-"
    mitm = ", ".join(summary.get("mitm") or []) or "-"
    msf = ", ".join(os.path.basename(p) for p in summary.get("msf") or []) or "-"
    text = "\n".join([
        f"### Auto engagement summary — {summary['target']}",
        f"- subdomains: {summary['subdomains']}",
        f"- open ports: {ports}",
        f"- live web: {', '.join(summary['web']) or '-'}",
        f"- mitm audits: {mitm}",
        f"- msf runbooks: {msf}",
        f"- findings recorded: {summary['findings']}",
        f"- report: {os.path.join(C.OUTPUT_DIR, 'report-' + session['name'] + '.md')}",
    ])
    console.assistant(text)
