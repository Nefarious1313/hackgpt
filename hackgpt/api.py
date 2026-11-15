"""Thin OpenAI-compatible client for the Nous inference endpoint.

Reuses the OAuth bearer that Hermes stores in ~/.hermes/auth.json, so no
separate API key is required. The token is re-read before every request so a
refresh performed by Hermes is picked up automatically.
"""
from __future__ import annotations

import json
import typing as t
import urllib.error
import urllib.request

from . import config as C


class APIError(RuntimeError):
    pass


class APIAuthError(APIError):
    pass


class NousAPI:
    def __init__(self, cfg: dict[str, t.Any]):
        self.cfg = cfg
        self.base = cfg.get("base_url", C.DEFAULT_CONFIG["base_url"]).rstrip("/")
        self.model = cfg.get("model", C.DEFAULT_CONFIG["model"])
        self.timeout = 180

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": "Bearer " + C.get_token(self.cfg),
            "Content-Type": "application/json",
        }

    def complete(
        self,
        messages: list[dict[str, t.Any]],
        tools: list[dict[str, t.Any]] | None = None,
        tool_choice: str = "auto",
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> dict[str, t.Any]:
        payload: dict[str, t.Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": self.cfg.get("temperature", 0.3) if temperature is None else temperature,
            "max_tokens": self.cfg.get("max_tokens", 4096) if max_tokens is None else max_tokens,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = tool_choice

        req = urllib.request.Request(
            self.base + "/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers=self._headers(),
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.load(resp)
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")[:500]
            if exc.code in (401, 403):
                raise APIAuthError(
                    f"Nous auth failed ({exc.code}). Hermes' bearer may have expired — "
                    f"run `hermes auth status` / re-login, then retry. {body}"
                ) from exc
            raise APIError(f"Nous API error {exc.code}: {body}") from exc
        except urllib.error.URLError as exc:
            raise APIError(f"Nous API unreachable: {exc}") from exc

        try:
            return data["choices"][0]["message"]
        except (KeyError, IndexError) as exc:
            raise APIError(f"Unexpected API response: {json.dumps(data)[:500]}") from exc
