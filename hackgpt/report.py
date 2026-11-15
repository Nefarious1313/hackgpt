"""Markdown engagement report rendering."""
from __future__ import annotations

import time
import typing as t


def render_markdown(session: dict, config: dict) -> str:  # noqa: ARG001
    name = session.get("name", "engagement")
    objective = session.get("objective") or "(not stated)"
    scope = config.get("scope", [])
    scope_txt = ", ".join((e if isinstance(e, str) else e.get("target", "")) for e in scope) or "(empty)"

    lines: list[str] = [
        f"# HackGPT Engagement Report — {name}",
        "",
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"Model: {config.get('model', '-')}",
        "",
        "## Objective",
        objective,
        "",
        "## Authorized Scope",
        scope_txt,
        "",
    ]

    findings = session.get("findings", [])
    lines += [f"## Findings ({len(findings)})", ""]
    if findings:
        for f in findings:
            cat = f.get("category", "finding")
            lines.append(f"### [{cat.upper()}] {f.get('text', '')}")
            if f.get("evidence"):
                lines += ["", "```", str(f["evidence"])[:2000], "```"]
            lines.append("")
    else:
        lines += ["_No findings recorded._", ""]

    targets = session.get("targets", [])
    lines += [f"## Targets ({len(targets)})", ""]
    if targets:
        for tg in targets:
            if "open_ports" in tg:
                lines.append(f"### {tg['target']}")
                lines += ["| port | service | version |", "| --- | --- | --- |"]
                for p in tg["open_ports"]:
                    lines.append(f"| {p['port']} | {p['service']} | {p['version']} |")
                lines.append("")
            elif "subdomains" in tg:
                lines.append(f"### {tg['target']} — {len(tg['subdomains'])} subdomains")
                lines.append(", ".join(tg["subdomains"][:200]))
                lines.append("")
            else:
                lines.append(f"- {tg.get('target')}")
    else:
        lines += ["_No targets enumerated._", ""]

    creds = session.get("credentials", [])
    lines += [f"## Credentials ({len(creds)})", ""]
    lines += [f"- {c.get('host','')}: {c.get('text','')}" for c in creds] or ["_None recorded._"]
    lines.append("")

    actions = session.get("actions", [])
    lines += [f"## Actions Log ({len(actions)})", ""]
    if actions:
        lines += ["| time | tool | detail |", "| --- | --- | --- |"]
        for a in actions[-200:]:
            detail = a.get("cmd") or a.get("target") or a.get("url") or a.get("domain") or ""
            detail = str(detail).replace("|", "\\|")[:160]
            lines.append(f"| {a.get('ts','')} | {a.get('tool','')} | {detail} |")
    else:
        lines += ["_No actions recorded._"]
    lines.append("")

    artifacts = session.get("artifacts", [])
    lines += [f"## Artifacts ({len(artifacts)})", ""]
    lines += [f"- `{p}`" for p in artifacts] or ["_None._"]
    lines.append("")

    lines += [
        "## Recommendations",
        "",
        "- Validate every finding manually before acting on it; automated output can be wrong.",
        "- Re-scan critical hosts with a second tool/profile to confirm exposure.",
        "- Rotate any credentials handled during this engagement and prefer least-privilege.",
        "- Keep evidence (screenshots, raw outputs) outside this report for the full audit trail.",
        "",
    ]
    return "\n".join(lines)
