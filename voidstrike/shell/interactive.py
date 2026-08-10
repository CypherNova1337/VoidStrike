"""A minimal interactive REPL over an :class:`RCEChannel`."""

from __future__ import annotations

import asyncio

from ..banner import BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW
from .channel import ChannelError, RCEChannel

_HELP = """\
Commands:
  <any shell command>   run it on the target and print output
  :info                 show the injection point backing this shell
  :help                 show this help
  :exit / :quit         leave the shell
"""


class InteractiveShell:
    def __init__(self, channel: RCEChannel, use_color: bool = True):
        self.channel = channel
        self.use_color = use_color

    def _c(self, text: str, code: str) -> str:
        return f"{code}{text}{RESET}" if self.use_color else text

    async def start(self) -> None:
        ok = await self.channel.check()
        if not ok:
            print(self._c("[!] Channel self-check failed — the target did not return "
                          "delimited output. Aborting.", RED))
            return
        f = self.channel.finding
        print(self._c(f"[+] Interactive channel established via {f.module} at "
                      f"{f.injection_point}", GREEN))
        print(self._c("    Authorized testing only. Commands run on the target host.",
                      YELLOW))
        print(self._c(_HELP, DIM))
        prompt = self._c("voidstrike:shell$ ", BOLD + CYAN)

        loop = asyncio.get_event_loop()
        while True:
            try:
                line = (await loop.run_in_executor(None, input, prompt)).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not line:
                continue
            if line in (":exit", ":quit"):
                break
            if line == ":help":
                print(self._c(_HELP, DIM))
                continue
            if line == ":info":
                print(self._c(f"    module={f.module} url={f.url} "
                              f"point={f.injection_point} oracle={f.oracle}", DIM))
                continue
            try:
                out = await self.channel.run(line)
                print(out.rstrip("\n") if out.strip() else self._c("(no output)", DIM))
            except ChannelError as exc:
                print(self._c(f"[!] {exc}", RED))
        print(self._c("[*] Channel closed.", DIM))
