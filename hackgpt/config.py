"""HackGPT configuration, scope enforcement, and session state.

Everything lives under ~/hackgpt (override with HACKGPT_HOME):
  config.yaml          model/provider settings, scope list, behavior flags
  sessions/<name>.json engagement state (messages, findings, action log)
  work/<name>/         scratch dir used as cwd for shell commands
  output/              generated reports / exploit artifacts
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import typing as t

import yaml

HOME = os.path.expanduser("~")
APP_DIR = os.environ.get("HACKGPT_HOME", os.path.join(HOME, "hackgpt"))
CONFIG_PATH = os.path.join(APP_DIR, "config.yaml")
SESSION_DIR = os.path.join(APP_DIR, "sessions")
WORK_DIR = os.path.join(APP_DIR, "work")
OUTPUT_DIR = os.path.join(APP_DIR, "output")

DEFAULT_CONFIG: dict[str, t.Any] = {
    "model": "meituan/longcat-2.5:free",
    "base_url": "https://inference-api.nousresearch.com/v1",
    "provider": "nous",
    "auth_path": os.path.join(HOME, ".hermes", "auth.json"),
    # Red-team behaviour controls
    "enforce_scope": True,
    "confirm_shell": False,
    "auto": True,
    "max_tool_iterations": 30,
    "temperature": 0.3,
    "max_tokens": 4096,
    # External tools
    "nmap": "nmap",
    "ncat": "ncat",
    "curl": "curl",
    "timeout_default": 90,
    "user_agent": "HackGPT/1.0 (red-team-copilot)",
    # Metasploit: search/planning/payload generation are always available;
    # module execution (msf_exec) is opt-in and scope-bound.
    "msfconsole": "msfconsole",
    "msfvenom": "msfvenom",
    "msf_execute": False,
    "msf_confirm": True,
    # Remote Metasploit RPC (msfrpcd). Point host at a box running msfrpcd,
    # preferably reachable through an SSH tunnel (127.0.0.1).
    "msfrpcd_host": "",
    "msfrpcd_port": 55553,
    "msfrpcd_user": "msf",
    "msfrpcd_pass": "",
    "msfrpcd_ssl": False,
    "msfrpcd_timeout": 60,
    # Authorized engagement scope (populated with the `scope` tool)
    "scope": [],
    "exclude": [],
}


def ensure_dirs() -> None:
    for d in (APP_DIR, SESSION_DIR, WORK_DIR, OUTPUT_DIR):
        os.makedirs(d, exist_ok=True)


def load_config() -> dict[str, t.Any]:
    ensure_dirs()
    cfg = dict(DEFAULT_CONFIG)
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            user = yaml.safe_load(fh) or {}
        cfg.update({k: v for k, v in user.items() if k in DEFAULT_CONFIG or k in ("scope", "exclude")})
    return cfg


def save_config(cfg: dict[str, t.Any]) -> None:
    ensure_dirs()
    with open(CONFIG_PATH, "w", encoding="utf-8") as fh:
        yaml.safe_dump(cfg, fh, sort_keys=False, allow_unicode=True)


def load_session(name: str) -> dict[str, t.Any]:
    path = os.path.join(SESSION_DIR, f"{name}.json")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    return {
        "name": name,
        "objective": "",
        "messages": [],
        "findings": [],
        "targets": [],
        "credentials": [],
        "actions": [],
        "artifacts": [],
        "started": None,
        "updated": None,
    }


def save_session(session: dict[str, t.Any]) -> None:
    ensure_dirs()
    path = os.path.join(SESSION_DIR, f"{session['name']}.json")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(session, fh, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def get_token(cfg: dict[str, t.Any]) -> str:
    """Read the OAuth bearer from Hermes auth state (refreshed in place by Hermes)."""
    path = cfg.get("auth_path", DEFAULT_CONFIG["auth_path"])
    provider = cfg.get("provider", "nous")
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    tok = data["providers"][provider]["access_token"]
    if not tok:
        raise RuntimeError(f"No access token for provider '{provider}' in {path}")
    return tok


# --------------------------------------------------------------------------
# Target scope handling
# --------------------------------------------------------------------------

_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")


def normalize_target(target: str) -> str:
    """Reduce a URL/host/IP/string to a bare host or IP."""
    if not target:
        return ""
    t = str(target).strip()
    t = _SCHEME.sub("", t)
    t = t.split("/", 1)[0]
    t = t.split("?", 1)[0]
    t = t.split("#", 1)[0]
    # strip userinfo
    if "@" in t:
        t = t.rsplit("@", 1)[1]
    # strip port (but keep IPv6 brackets handled below)
    if t.startswith("["):
        end = t.find("]")
        if end != -1:
            return t[1:end]
    if t.count(":") == 1:
        t = t.split(":", 1)[0]
    return t.lower()


def _norm_scope_entry(raw: t.Any) -> str:
    """Normalize a scope entry, preserving CIDR notation.

    `normalize_target` strips everything after '/', which would turn
    '203.0.113.0/24' into '203.0.113.0' and silently break CIDR matching.
    """
    raw = str(raw or "").strip()
    if not raw:
        return ""
    try:
        ipaddress.ip_network(raw, strict=False)
        return raw.lower()
    except ValueError:
        pass
    return normalize_target(raw)


def _scope_entries(scope: t.Sequence[t.Any]) -> list[str]:
    out: list[str] = []
    for e in scope or []:
        if isinstance(e, str):
            out.append(e)
        elif isinstance(e, dict):
            out.append(e.get("target", ""))
    return [_norm_scope_entry(x) for x in out if x]


def target_in_scope(target: str, scope: t.Sequence[t.Any]) -> bool:
    """True if `target` (host/IP/URL/CIDR) falls inside any scope entry."""
    entries = _scope_entries(scope)
    if not entries:
        return False
    if any(e == "*" for e in entries):
        return True
    t = normalize_target(target)
    if not t:
        return False

    try:
        tip = ipaddress.ip_address(t)
    except ValueError:
        tip = None

    for e in entries:
        if e == "*":
            return True
        # exact host
        if t == e:
            return True
        # domain suffix
        if t.endswith("." + e):
            return True
        # wildcard entry like *.example.com
        if e.startswith("*.") and t.endswith(e[1:]):
            return True
        # CIDR / IP
        try:
            net = ipaddress.ip_network(e, strict=False)
        except ValueError:
            continue
        if tip is not None and tip in net:
            return True
    return False


class ScopeDenied(RuntimeError):
    pass


def require_scope(cfg: dict[str, t.Any], target: str) -> None:
    if not cfg.get("enforce_scope", True):
        return
    if target_in_scope(target, cfg.get("scope", [])):
        return
    raise ScopeDenied(
        f"target '{target}' is outside the authorized scope. "
        f"Add it first with the `scope` tool (scope add {target}) or start "
        f"with --no-scope for a lab/CTF engagement."
    )


def which(binary: str) -> str | None:
    return shutil.which(binary)
