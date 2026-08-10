"""Interpreted-language code injection detection (eval-style sinks).

Delegates payload selection to the Brain, which draws PHP/Python/Ruby/Perl/Node
manoeuvres from the corpus. Proofs echo the marker or fall back to a timing
oracle for blind cases.
"""

from __future__ import annotations

from ..engine.models import Confidence, Severity, Target
from .base import Module


class CodeInjection(Module):
    name = "code_injection"
    vuln_class = "Server-Side Code Injection"
    severity = Severity.CRITICAL
    remediation = (
        "Remove dynamic evaluation of user input (eval/exec/Function/System). "
        "Where dynamic behavior is required, use a safe interpreter or a strict "
        "allow-list, and never concatenate request data into code."
    )

    async def run(self, target: Target) -> None:
        for point in target.injection_points():
            marker = self.marker()
            context = f"eval-style code injection at {point.describe()} on {target.url}"
            payloads = await self.plan(marker=marker, context=context, oracle="output")
            if await self.try_payloads(point, payloads, marker, oracle="output"):
                continue
            await self._confirm_time(point)

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
                        f"time-based eval: {confirm.elapsed:.1f}s vs {baseline:.1f}s"
                    )
                    self._record(confirm, oracle="time", confidence=Confidence.FIRM)
                    return True
        return False
