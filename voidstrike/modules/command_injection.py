"""OS command injection detection.

The module is thin: it asks the Brain to plan manoeuvres from the built-in
corpus (Unix/Windows separators, quote breakouts, IFS/evasion, time-based and
OOB variants) and drives the three oracles. All proofs are non-destructive —
echo a random marker, sleep briefly, or trigger an out-of-band lookup.
"""

from __future__ import annotations

from ..engine.models import Confidence, Severity, Target
from .base import Module


class CommandInjection(Module):
    name = "cmd_injection"
    vuln_class = "OS Command Injection"
    severity = Severity.CRITICAL
    remediation = (
        "Never pass user input to a shell. Use parameterized process APIs "
        "(execve with an argument vector, subprocess with shell=False), strict "
        "allow-lists, and drop shell metacharacters. Run with least privilege."
    )

    async def run(self, target: Target) -> None:
        for point in target.injection_points():
            marker = self.marker()
            context = (f"OS command injection at {point.describe()} on {target.url}; "
                       f"baseline value {point.baseline_value!r}")

            # 1) Output-based (non-blind).
            payloads = await self.plan(marker=marker, context=context, oracle="output")
            if await self.try_payloads(point, payloads, marker, oracle="output"):
                continue
            # 2) Time-based blind.
            if await self._confirm_time(point):
                continue
            # 3) Out-of-band blind.
            await self._confirm_oob(point)

    async def _confirm_time(self, point) -> bool:
        seconds = 6
        payloads = await self.plan(sleep=seconds, oracle="time")
        baseline = await self.s.baseline(point)
        threshold = baseline + (seconds - 1.5)
        for payload in payloads:
            result = await self.s.probe(point=point, payload=payload, marker="",
                                        vuln_class=self.vuln_class, module=self.name)
            if result is None:
                return False
            if result.elapsed >= threshold:
                confirm = await self.s.probe(point=point, payload=payload, marker="",
                                             vuln_class=self.vuln_class, module=self.name)
                if confirm and confirm.elapsed >= threshold:
                    confirm.verdict.verdict = "executed"
                    confirm.verdict.confidence = 0.85
                    confirm.verdict.signal = (
                        f"time-based: {confirm.elapsed:.1f}s vs baseline {baseline:.1f}s"
                    )
                    self._record(confirm, oracle="time", confidence=Confidence.FIRM)
                    return True
        return False

    async def _confirm_oob(self, point) -> bool:
        if not self.s.oob.active:
            return False
        token = self.s.oob.new_token("ci")
        host = self.s.oob.callback_host(token)
        payloads = await self.plan(host=host, oracle="oob")
        for payload in payloads:
            result = await self.s.probe(point=point, payload=payload, marker="",
                                        vuln_class=self.vuln_class, module=self.name)
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
