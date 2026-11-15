"""Shared fixtures for the HackGPT test suite."""
from __future__ import annotations

import tempfile

from hackgpt.tools import Ctx


class FakeConsole:
    """Minimal stand-in for ui.Console."""

    def __init__(self) -> None:
        self.actions: list[tuple[str, str]] = []
        self.output: list[str] = []

    def log_action(self, tool: str, detail: str = "") -> None:
        self.actions.append((tool, detail))

    def confirm(self, prompt: str) -> bool:
        return True

    def status(self, msg: str) -> None:
        self.output.append(msg)

    def error(self, msg: str) -> None:
        self.output.append(msg)

    def assistant(self, msg: str) -> None:
        self.output.append(msg)

    def tool(self, msg: str) -> None:
        self.output.append(msg)

    def banner(self, msg: str) -> None:
        pass

    def ask(self, prompt: str) -> str:
        return "/exit"


def make_ctx(scope: list[str] | None = None, enforce: bool = True,
             dry_run: bool = False, name: str = "t") -> Ctx:
    cfg = {
        "enforce_scope": enforce,
        "scope": [{"target": t, "added": "test"} for t in (scope or [])],
        "timeout_default": 5,
        "user_agent": "hackgpt-test",
        "nmap": "nmap",
        "ncat": "ncat",
        "curl": "curl",
    }
    session = {
        "name": name,
        "objective": "test",
        "messages": [],
        "findings": [],
        "targets": [],
        "credentials": [],
        "actions": [],
        "artifacts": [],
    }
    return Ctx(
        config=cfg,
        session=session,
        console=FakeConsole(),
        workdir=tempfile.mkdtemp(prefix="hackgpt-work-"),
        output_dir=tempfile.mkdtemp(prefix="hackgpt-out-"),
        dry_run=dry_run,
    )
