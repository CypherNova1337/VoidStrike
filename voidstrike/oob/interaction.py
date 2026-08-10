"""Out-of-band interaction manager (OAST).

Blind RCE — where command output is never reflected back in the HTTP
response — is confirmed by making the target reach out to infrastructure the
tester controls. This module mints unique correlation tokens, embeds them in
DNS/HTTP callbacks, and reconciles received interactions back to the payload
that triggered them.

Two collection strategies are supported:

* **Listener**  — a local async HTTP server catches callbacks when you control
  the network path to the target (e.g. an internal engagement).
* **Collaborator** — a hosted OAST domain (Interactsh-style) is polled via an
  operator-supplied ``poll_url``.

Both are optional; if neither is configured the manager degrades gracefully
and blind checks simply report "unconfirmed".
"""

from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import dataclass, field

from ..config import OOBConfig


@dataclass
class Interaction:
    token: str
    protocol: str  # "dns" | "http"
    source_ip: str = ""
    raw: str = ""
    received_at: float = field(default_factory=time.time)


class OOBManager:
    def __init__(self, config: OOBConfig):
        self.config = config
        self._interactions: list[Interaction] = []
        self._tokens: set[str] = set()
        self._server: asyncio.AbstractServer | None = None

    @property
    def active(self) -> bool:
        return bool(
            self.config.enabled
            and (self.config.collaborator_domain or self.config.listener_port)
        )

    def new_token(self, prefix: str = "vs") -> str:
        token = f"{prefix}{secrets.token_hex(6)}"
        self._tokens.add(token)
        return token

    def callback_host(self, token: str) -> str:
        """Return a hostname the target should resolve/contact for ``token``."""
        if self.config.collaborator_domain:
            return f"{token}.{self.config.collaborator_domain}"
        return token  # bare token — only useful with a local listener + DNS

    async def start(self) -> None:
        if self.config.listener_port:
            await self._start_listener()

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _start_listener(self) -> None:
        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=5)
                text = data.decode(errors="replace")
                peer = writer.get_extra_info("peername")
                ip = peer[0] if peer else ""
                for token in self._tokens:
                    if token in text:
                        self._interactions.append(
                            Interaction(token=token, protocol="http",
                                        source_ip=ip, raw=text[:512])
                        )
                writer.write(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                )
                await writer.drain()
            except (asyncio.TimeoutError, ConnectionError):
                pass
            finally:
                writer.close()

        self._server = await asyncio.start_server(
            handle, self.config.listener_host, self.config.listener_port
        )

    async def poll(self) -> list[Interaction]:
        """Pull new interactions from a hosted collaborator, if configured."""
        if not self.config.poll_url:
            return []
        # The poll endpoint contract is operator-defined; we look for any token
        # substring in the returned body. This keeps VoidStrike compatible with
        # many self-hosted OAST services without hard-coding one.
        try:
            import json
            import urllib.request

            with urllib.request.urlopen(self.config.poll_url, timeout=10) as resp:
                body = resp.read().decode(errors="replace")
        except Exception:  # noqa: BLE001
            return []
        found: list[Interaction] = []
        for token in self._tokens:
            if token in body:
                inter = Interaction(token=token, protocol="dns", raw=body[:512])
                self._interactions.append(inter)
                found.append(inter)
        return found

    async def wait_for(self, token: str, timeout: float = 8.0,
                       interval: float = 1.0) -> Interaction | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            hit = self.find(token)
            if hit:
                return hit
            if self.config.poll_url:
                await self.poll()
                hit = self.find(token)
                if hit:
                    return hit
            await asyncio.sleep(interval)
        return None

    def find(self, token: str) -> Interaction | None:
        for inter in self._interactions:
            if inter.token == token:
                return inter
        return None

    @property
    def interactions(self) -> list[Interaction]:
        return list(self._interactions)
