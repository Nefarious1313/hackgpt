# HACKGPT — terminal red-team copilot

A custom, local, terminal-native offensive-security copilot wrapped around the
free Nous inference model (`meituan/longcat-2.5:free` by default). It plans an
engagement, drives real tools (nmap, DNS, HTTP, CVE research, payload
generation, encoding, IP intel, TLS, directory checks and read-only MITM
resilience auditing), records findings, and writes a markdown report. Its
three-layer Metasploit integration covers catalog search, `msfvenom` payload
generation and reviewed `.rc` runbooks — with opt-in module execution. Point it
at a target and it runs the whole engagement itself (`--auto` / `--full`), or
pick a numbered option from `--menu`.

Nothing leaves the device except the API calls to the Nous endpoint and whatever
targets you point it at. The OAuth bearer is read from Hermes' auth state
(`~/.hermes/auth.json`), so no separate key is needed.

## Install

Already installed on this machine:

- Project: `~/hackgpt/`
- Entry point: `hackgpt` → symlink to `~/hackgpt/hackgpt.py` (on PATH via `~/.local/bin`)
- Deps: Python 3.14 + `requests`/`httpx`/`yaml`/`rich` (present), `nmap`, `ncat`, `curl`, `jq`

Verify:

```bash
hackgpt --version
hackgpt --help
```

## Quick start

```bash
# Simplest: one target, full pipeline, report (no model needed)
hackgpt --auto example.com

# Maximal pipeline: recon -> scan -> web -> MITM audit -> MSF runbooks -> report
hackgpt --full example.com

# Guided numbered menu
hackgpt --menu

# One-shot AI objective (local work needs no scope)
hackgpt "Check what's listening locally and summarize the risk."

# Scoped remote engagement
hackgpt --session acme --scope example.com --scope 203.0.113.0/24 \
        "Recon example.com: subdomains, DNS, open ports, then web checks."

# Interactive console (resumable, slash commands)
hackgpt --session acme
hackgpt> /scope add example.com
hackgpt> enumerate subdomains for example.com
hackgpt> /report save
hackgpt> /exit
```

Useful flags: `--dry-run` (no execution, including network probes), `--confirm`
(confirm each shell command), `--no-scope` (lab/CTF), `--report` (save report on
exit), `--reset` (fresh history), `--model <id>` (swap model).

## One-command modes (deterministic, no model needed)

`--auto`, `--quick`, `--web` and `--menu` drive the tools directly, so they work
even while the Nous free tier is at capacity.

```bash
hackgpt --auto example.com            # recon -> scan -> web -> report
hackgpt --full example.com            # + MITM audits + Metasploit runbook planning
hackgpt --auto 203.0.113.0/24 --deep --research
hackgpt --quick example.com           # nmap top100 + web probe
hackgpt --web https://example.com      # headers/methods/CORS/paths + TLS
hackgpt --watch-dns example.com --interval 3600 --count 0  # monitor DNS until Ctrl-C
hackgpt --dry-run --watch-dns example.com --count 1       # preview a single poll
hackgpt --menu                        # guided menu (option 10 watches DNS)
hackgpt --doctor                      # check deps / auth / model
hackgpt --doctor --fix                # install what is missing
```

Every mode writes `sessions/<name>.json` and `output/report-<name>.md`. `--auto`
seeds the scope for the target automatically; `--deep` uses `nmap -p- -sV`;
`--research` adds a short CVE pass over discovered services. Add `--dry-run` to
preview without touching the network or the host. `--msf-exec` allows a full
engagement to execute the generated Metasploit runbooks (scope-bound, confirmed
unless `--msf-no-confirm`).

## Scope model

Offensive tools (`nmap_scan`, `http_probe`, `web_vuln_scan`, `dns_recon`,
`subdomain_enum`, `ip_info`, `tls_cert`, `web_dirs`, `mitm_audit`,
`dns_snapshot`, and the RHOSTS of `msf_plan`/`msf_exec`) refuse targets outside
the authorized scope. `shell` runs on the operator host and is never
scope-bound. Scope lives in `~/hackgpt/config.yaml` and is managed with the
`scope` tool or `/scope`.

Scope entries accept hosts, domains, IPs, CIDR ranges, and `*.domain` wildcards.
`--no-scope` disables enforcement for lab/CTF use.

Metasploit is layered. Catalog search, `msfvenom` payload generation and
runbook planning are always available. Executing modules with `msf_exec`
requires explicit enablement (`msf_execute: true` in config.yaml, or
`--msf-exec`), keeps every RHOSTS entry inside scope, and asks for confirmation
unless `msf_confirm` is disabled (or `--msf-no-confirm` is passed).

## Toolset

| Tool | Purpose |
| --- | --- |
| `shell` | Run a command on the operator host (cwd = session workdir) |
| `nmap_scan` | Port/service scan; profiles quick, top100, full, service, vuln, stealth, udp |
| `http_probe` | Fetch a URL: status, headers, title, size |
| `web_vuln_scan` | Security headers, methods, CORS, sensitive paths, tech fingerprint |
| `dns_recon` | A/AAAA/CNAME/MX/NS/TXT/SOA + whois |
| `subdomain_enum` | crt.sh + HackerTarget enumeration |
| `cve_lookup` | CVE by id or keyword (cve.circl.lu) |
| `exploit_search` | Local exploit DB (searchsploit) + CVE references |
| `payload_gen` | Labeled reverse-shell / download payloads (bash, nc, socat, awk, python, php, powershell, …) |
| `listener` | Start/stop a local ncat catch listener |
| `encode` | Encode/decode base64, hex, url, rot13, and decode JWTs |
| `hash_info` | Identify a password hash format from its structure |
| `ip_info` | IP/CIDR ownership, ASN, geolocation (ipinfo.io) |
| `tls_cert` | Fetch and parse the TLS certificate for host:port (openssl) |
| `web_dirs` | Probe common paths or a supplied wordlist on a web server |
| `dns_snapshot` | Persist scoped A/AAAA baseline and report DNS changes |
| `msf_catalog` | Check Metasploit availability / search its module catalog (auxiliary, exploit, post, payload, …); search-only |
| `msf_payload` | Generate a Metasploit payload with msfvenom into a file (elf, exe, raw, apk, …) |
| `msf_plan` | Write a reviewed Metasploit `.rc` runbook for a module + in-scope RHOSTS |
| `msf_exec` | Execute a runbook via msfconsole — opt-in (`--msf-exec`), scope-bound, confirmed |
| `mitm_audit` | Read-only MITM-resilience audit: cert validity/hostname/chain, TLS versions, cipher strength, HSTS, plaintext fallback |
| `mitm_demo` | Local synthetic MITM attack-chain walkthrough + defensive checklist (no network) |
| `note` | Record findings/credentials/targets with evidence |
| `scope` | list/add/remove/check authorized targets |
| `file_write` | Write an artifact (exploit, wordlist, script) |
| `report` | Show/save the engagement report |

## Layout

```
~/hackgpt/
├── hackgpt.py          # CLI entry (argparse, agent loop, REPL)
├── hackgpt/
│   ├── api.py          # Nous OpenAI-compatible client (token from Hermes)
│   ├── config.py       # config, scope engine, session persistence
│   ├── prompts.py      # persona + system prompt
│   ├── tools.py        # tool schemas + handlers (the capability layer)
│   ├── automation.py   # doctor + deterministic one-command engagements
│   ├── menu.py         # guided numbered menu
│   ├── report.py       # markdown report renderer
│   └── ui.py           # rich/plain terminal I/O
├── config.yaml         # model, flags, scope (created on first run)
├── sessions/<name>.json
├── work/<name>/        # shell cwd per engagement
├── tests/              # unittest suite (scope, tools, agent loop)
├── run_tests.sh        # test runner
└── output/             # reports + artifacts
```

## Extending

Add a tool in `hackgpt/tools.py`:

1. Write a handler `def h_my_tool(args, ctx) -> str` (call `C.require_scope`
   for remote targets, mutate `ctx.session` for findings).
2. Register it in `HANDLERS` and add a schema to `TOOLS`.

The model sees `TOOLS` on every call and dispatches through `HANDLERS`.

## Testing

```bash
cd ~/hackgpt
bash run_tests.sh          # or: python3 -m unittest discover -s tests -t .
```

The suite runs fully offline against an isolated `HACKGPT_HOME` (a temp dir), so
it never touches the real `config.yaml`, sessions or output. It covers the scope
engine (host/domain/CIDR/wildcard/deny), target normalization, session/config
persistence, every utility handler, scope enforcement, dry-run behaviour, tool
registry consistency, and the agent loop's tool dispatch + prose-JSON fallback.

## Notes / pitfalls

- The Nous bearer is short-lived; if a run fails with 401, re-auth Hermes
  (`hermes auth status`) and retry. The token is re-read before each request.
- The Nous free tier can return `429` ("at capacity upstream"). That is
  transient and not a key problem — the CLI reports it, keeps the session, and
  exits cleanly; just retry.
- If a model emits a JSON tool call in prose instead of native calling, the CLI
  parses and executes it (fallback, including nested `arguments` objects), so
  behaviour is stable across models.
- `--dry-run` suppresses shell, nmap, http_probe, web_vuln_scan, web_dirs,
  ip_info, tls_cert and listener — it does not touch the network or the host.
- `dns_recon` resolves A/AAAA through the system resolver when `dig`/`nslookup`
  are absent; install `dnsutils` (`hackgpt --doctor --fix`) for MX/NS/TXT/SOA.
- Active scans are rate-limited by profile; keep `stealth`/`udp` for ranges you
  own (they need raw sockets / root).
- Metasploit is not packaged for Termux, so `--doctor` reports `msfconsole` /
  `msfvenom` as absent. Catalog search, payload generation and runbook planning
  degrade gracefully (they say what is missing); point `msfconsole`/`msfvenom`
  in config.yaml at a local install or an SSH wrapper to use them live.
- Only test systems you are authorized to test. Scope enforcement is on by
  default; `--no-scope` is for labs and CTFs.
