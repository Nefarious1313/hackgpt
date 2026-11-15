"""Terminal I/O helpers (rich when available, plain fallback)."""
from __future__ import annotations

import sys
import typing as t

try:
    from rich.console import Console as _Rich
    from rich.panel import Panel
    from rich.markdown import Markdown
except Exception:  # pragma: no cover
    _Rich = None  # type: ignore


class Console:
    def __init__(self, quiet: bool = False):
        self.quiet = quiet
        self._rich = None if (quiet or _Rich is None) else _Rich()
        self._log: list[tuple[str, str]] = []

    # -- output -----------------------------------------------------------
    def banner(self, text: str) -> None:
        if self._rich:
            self._rich.print(Panel(text, title="HACKGPT", border_style="red", expand=False))
        elif not self.quiet:
            print("=" * 60)
            print("HACKGPT")
            print(text)
            print("=" * 60)

    def assistant(self, text: str) -> None:
        if not text:
            return
        if self._rich:
            self._rich.print(Markdown(text))
        else:
            print(text)

    def status(self, text: str) -> None:
        if self._rich:
            self._rich.print(f"[cyan]{text}[/cyan]")
        elif not self.quiet:
            print(f"[*] {text}")

    def error(self, text: str) -> None:
        if self._rich:
            self._rich.print(f"[bold red]{text}[/bold red]")
        else:
            print(f"[!] {text}", file=sys.stderr)

    def tool(self, text: str) -> None:
        if self._rich:
            self._rich.print(f"[dim]{text}[/dim]")
        elif not self.quiet:
            print(f"    {text}")

    def log_action(self, tool_name: str, detail: str) -> None:
        self._log.append((tool_name, detail))
        self.tool(f"-> {tool_name}: {detail[:160]}")

    # -- input ------------------------------------------------------------
    def confirm(self, prompt: str) -> bool:
        if self._rich:
            from rich.prompt import Confirm

            try:
                return bool(Confirm.ask(prompt, default=False, console=self._rich))
            except Exception:  # noqa: BLE001
                pass
        try:
            ans = input(f"{prompt} [y/N] ").strip().lower()
        except EOFError:
            return False
        return ans in ("y", "yes")

    def ask(self, prompt: str) -> str:
        if self._rich:
            from rich.prompt import Prompt

            try:
                return str(Prompt.ask(prompt, console=self._rich))
            except Exception:  # noqa: BLE001
                pass
        try:
            return input(f"{prompt} ").strip()
        except EOFError:
            return ""
