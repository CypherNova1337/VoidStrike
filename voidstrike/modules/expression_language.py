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

    async def run(self, target: Target) -> None:
        # JNDI is frequently reachable via logged headers; include common ones.
        for point in target.injection_points():
            await self._check_el(point)
            await self._check_jndi(point)

    async def _check_el(self, point) -> bool:
        marker = self.marker()
        # OGNL / SpEL / MVEL execution payloads planned from the corpus.
        payloads = await self.plan(marker=marker, oracle="output",
                                   context=f"OGNL/SpEL EL injection at {point.describe()}")
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
        payloads = await self.plan(host=host, oracle="oob",
                                   context="JNDI/Log4Shell lookup")
        for payload in payloads:
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
