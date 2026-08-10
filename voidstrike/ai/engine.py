"""Provider-agnostic LLM engine.

VoidStrike does not hard-code any single AI vendor. Point ``AIConfig`` at any
HTTP endpoint that speaks one of the supported wire formats:

* ``openai_compatible`` — ``POST {base_url}/chat/completions`` with a
  ``messages`` array (works with many local and hosted gateways).
* ``messages`` — a generic messages endpoint returning ``{"content": "..."}``.
* ``generic`` — best-effort auto-detection of the two above.

Credentials are read from the environment variable named by
``AIConfig.api_key_env`` and are never persisted by VoidStrike.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from ..config import AIConfig


class AIEngine:
    def __init__(self, config: AIConfig):
        self.config = config
        self._backend = _select_backend()
        self._degraded_reason: str | None = None
        if not config.base_url or not config.model:
            self._degraded_reason = "LLM base_url/model not configured"
        elif not config.api_key:
            self._degraded_reason = f"env {config.api_key_env} is unset"

    @property
    def available(self) -> bool:
        return self.config.enabled and self._degraded_reason is None

    @property
    def status(self) -> str:
        if not self.config.enabled:
            return "disabled"
        if self._degraded_reason:
            return f"degraded ({self._degraded_reason})"
        return f"ready [{self.config.provider}:{self.config.model}]"

    async def complete(self, system: str, user: str) -> str:
        """Return the model's text completion, or "" if unavailable."""
        if not self.available:
            return ""
        try:
            return await self._dispatch(system, user)
        except Exception:  # noqa: BLE001 - AI is best-effort, never fatal
            return ""

    async def complete_json(self, system: str, user: str) -> Any:
        text = await self.complete(system, user)
        if not text:
            return None
        return _extract_json(text)

    # -- backends --------------------------------------------------------
    async def _dispatch(self, system: str, user: str) -> str:
        provider = self.config.provider
        payload, path = self._build_request(system, user)
        url = self.config.base_url.rstrip("/") + path
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config.api_key}",
        }
        body = await self._http_post(url, headers, payload)
        return _parse_completion(body)

    def _build_request(self, system: str, user: str) -> tuple[dict, str]:
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        base = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }
        if self.config.provider == "messages":
            return base, "/messages"
        return base, "/chat/completions"

    async def _http_post(self, url: str, headers: dict, payload: dict) -> dict:
        if self._backend == "httpx":
            import httpx  # type: ignore

            async with httpx.AsyncClient(timeout=self.config.request_timeout) as c:
                r = await c.post(url, headers=headers, json=payload)
                return r.json()
        return await asyncio.to_thread(_urllib_post_json, url, headers, payload,
                                       self.config.request_timeout)


def _select_backend() -> str:
    try:
        import httpx  # noqa: F401

        return "httpx"
    except ModuleNotFoundError:
        return "urllib"


def _urllib_post_json(url: str, headers: dict, payload: dict, timeout: float) -> dict:
    import urllib.request

    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode(errors="replace"))


def _parse_completion(body: dict) -> str:
    if not isinstance(body, dict):
        return ""
    # openai_compatible
    choices = body.get("choices")
    if isinstance(choices, list) and choices:
        msg = choices[0].get("message", {})
        if isinstance(msg, dict) and "content" in msg:
            return _as_text(msg["content"])
        if "text" in choices[0]:
            return _as_text(choices[0]["text"])
    # messages-style
    if "content" in body:
        return _as_text(body["content"])
    if "output_text" in body:
        return _as_text(body["output_text"])
    return ""


def _as_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts = []
        for item in value:
            if isinstance(item, dict):
                parts.append(str(item.get("text", "")))
            else:
                parts.append(str(item))
        return "".join(parts)
    return str(value)


def _extract_json(text: str) -> Any:
    text = text.strip()
    # Strip common code fences.
    if text.startswith("```"):
        text = text.split("```", 2)[1] if text.count("```") >= 2 else text
        if text.startswith(("json", "JSON")):
            text = text[4:]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Try to locate the first JSON object/array in the text.
    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        end = text.rfind(closer)
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                continue
    return None
