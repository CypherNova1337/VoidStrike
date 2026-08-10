"""Asynchronous HTTP client with rate limiting and a scope-aware guard.

The client prefers ``httpx`` when it is installed and transparently falls back
to a stdlib (``urllib``) backend executed in a thread pool, so VoidStrike runs
even in minimal environments. Every request is validated against the active
:class:`~voidstrike.authorization.ScopeGuard` before it leaves the process.
"""

from __future__ import annotations

import asyncio
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from .authorization import ScopeGuard
from .config import HttpConfig


@dataclass
class Response:
    status: int
    headers: dict
    text: str
    elapsed: float
    url: str
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and 0 < self.status < 600

    def header(self, name: str, default: str = "") -> str:
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return default


class RateLimiter:
    """Simple token-bucket rate limiter (requests per second)."""

    def __init__(self, rate: float):
        self.rate = max(rate, 0.01)
        self._allowance = self.rate
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._last = now
            self._allowance = min(self.rate, self._allowance + elapsed * self.rate)
            if self._allowance < 1.0:
                wait = (1.0 - self._allowance) / self.rate
                await asyncio.sleep(wait)
                self._allowance = 0.0
            else:
                self._allowance -= 1.0


class HttpClient:
    def __init__(self, config: HttpConfig, guard: ScopeGuard | None = None):
        self.config = config
        self.guard = guard
        self._sem = asyncio.Semaphore(config.max_concurrency)
        self._limiter = RateLimiter(config.requests_per_second)
        self._stats = {"sent": 0, "errors": 0}
        self._backend = _select_backend()
        self._client: Any = None

    async def __aenter__(self) -> "HttpClient":
        if self._backend == "httpx":
            import httpx  # type: ignore

            kwargs = {
                "timeout": self.config.timeout,
                "verify": self.config.verify_tls,
                "follow_redirects": True,
            }
            if self.config.proxy:
                # httpx >=0.28 uses `proxy`; older releases used `proxies`.
                try:
                    self._client = httpx.AsyncClient(proxy=self.config.proxy, **kwargs)
                except TypeError:
                    self._client = httpx.AsyncClient(proxies=self.config.proxy, **kwargs)
            else:
                self._client = httpx.AsyncClient(**kwargs)
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._client is not None:
            await self._client.aclose()

    @property
    def stats(self) -> dict:
        return dict(self._stats)

    async def request(self, method: str, url: str, *, params: dict | None = None,
                      data: Any = None, json: Any = None, headers: dict | None = None,
                      files: dict | None = None, allow_redirects: bool = True) -> Response:
        # Scope enforcement — refuses to touch out-of-scope hosts.
        if self.guard is not None:
            self.guard.check(url)

        merged_headers = {
            "User-Agent": self.config.user_agent,
            **self.config.default_headers,
            **(headers or {}),
        }

        last_exc: Exception | None = None
        for attempt in range(self.config.retries + 1):
            await self._limiter.acquire()
            async with self._sem:
                try:
                    resp = await self._dispatch(
                        method, url, params, data, json, merged_headers,
                        allow_redirects, files,
                    )
                    self._stats["sent"] += 1
                    return resp
                except Exception as exc:  # noqa: BLE001 - surfaced to caller as Response
                    last_exc = exc
                    if attempt < self.config.retries:
                        await asyncio.sleep(0.5 * (attempt + 1))
        self._stats["errors"] += 1
        return Response(0, {}, "", 0.0, url, error=str(last_exc))

    async def get(self, url: str, **kwargs) -> Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> Response:
        return await self.request("POST", url, **kwargs)

    # -- backends --------------------------------------------------------
    async def _dispatch(self, method, url, params, data, json, headers, redirects,
                        files=None):
        if self._backend == "httpx":
            start = time.monotonic()
            r = await self._client.request(
                method, url, params=params, data=data, json=json, headers=headers,
                files=files, follow_redirects=redirects,
            )
            return Response(r.status_code, dict(r.headers), r.text,
                            time.monotonic() - start, str(r.url))
        # stdlib fallback in a thread
        return await asyncio.to_thread(
            _urllib_request, method, url, params, data, json, headers,
            self.config.timeout, redirects, files,
        )


def _select_backend() -> str:
    try:
        import httpx  # noqa: F401

        return "httpx"
    except ModuleNotFoundError:
        return "urllib"


def _urllib_request(method, url, params, data, json_body, headers, timeout,
                    redirects, files=None):
    import json as _json
    from urllib.parse import urlencode

    if params:
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}{urlencode(params)}"

    body: bytes | None = None
    hdrs = dict(headers)
    if files:
        body, content_type = _encode_multipart(data if isinstance(data, dict) else None,
                                                files)
        hdrs.setdefault("Content-Type", content_type)
    elif json_body is not None:
        body = _json.dumps(json_body).encode()
        hdrs.setdefault("Content-Type", "application/json")
    elif data is not None:
        if isinstance(data, (dict, list)):
            body = urlencode(data).encode()
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif isinstance(data, str):
            body = data.encode()
        else:
            body = data

    req = urllib.request.Request(url, data=body, headers=hdrs, method=method.upper())
    start = time.monotonic()

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):  # pragma: no cover
            return None

    opener = urllib.request.build_opener(
        *( [] if redirects else [_NoRedirect()] )
    )
    try:
        with opener.open(req, timeout=timeout) as resp:
            text = resp.read().decode(errors="replace")
            return Response(resp.status, dict(resp.headers), text,
                            time.monotonic() - start, resp.geturl())
    except urllib.error.HTTPError as exc:
        text = exc.read().decode(errors="replace") if exc.fp else ""
        return Response(exc.code, dict(exc.headers or {}), text,
                        time.monotonic() - start, url)


def _encode_multipart(fields: dict | None, files: dict) -> tuple[bytes, str]:
    """Build a multipart/form-data body.

    ``files`` maps field name -> (filename, content, content_type). ``content``
    may be ``str`` or ``bytes``.
    """
    import secrets as _secrets

    boundary = "----VoidStrike" + _secrets.token_hex(12)
    crlf = b"\r\n"
    parts: list[bytes] = []
    for name, value in (fields or {}).items():
        parts.append(b"--" + boundary.encode() + crlf)
        parts.append(f'Content-Disposition: form-data; name="{name}"'.encode() + crlf + crlf)
        parts.append(str(value).encode() + crlf)
    for name, spec in files.items():
        filename, content, ctype = spec
        if isinstance(content, str):
            content = content.encode()
        parts.append(b"--" + boundary.encode() + crlf)
        parts.append(
            f'Content-Disposition: form-data; name="{name}"; filename="{filename}"'
            .encode() + crlf
        )
        parts.append(f"Content-Type: {ctype}".encode() + crlf + crlf)
        parts.append(content + crlf)
    parts.append(b"--" + boundary.encode() + b"--" + crlf)
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"
