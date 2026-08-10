"""Base class for detection modules."""

from __future__ import annotations

from ..engine.models import (
    Confidence,
    Finding,
    InjectionPoint,
    Severity,
    Target,
    new_marker,
)
from ..engine.session import ProbeResult, Session


class Module:
    """A detection module for one RCE vulnerability class.

    Subclasses implement :meth:`run`, iterating a target's injection points and
    calling :meth:`session.probe` with candidate payloads. Shared plumbing —
    AI-assisted payload expansion, filter adaptation, and finding construction —
    lives here so each module stays focused on its payload logic.
    """

    #: unique short id, e.g. "cmd_injection"
    name: str = "base"
    #: human-readable vulnerability class
    vuln_class: str = "Remote Code Execution"
    severity: Severity = Severity.HIGH
    remediation: str = ""

    def __init__(self, session: Session):
        self.s = session
        self.log = session.log

    async def run(self, target: Target) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    # -- helpers available to every module -------------------------------
    def marker(self) -> str:
        return new_marker()

    async def try_payloads(self, point: InjectionPoint, payloads: list[str],
                           marker: str, *, oracle: str = "output",
                           context: str = "") -> ProbeResult | None:
        """Send a batch of payloads; return the first that confirms execution.

        On a confirmed hit a :class:`Finding` is recorded automatically. If all
        payloads are blocked and an AI engine is available, the module asks it
        for filter-evasion variants (to map the client's WAF coverage) and
        retries once.
        """
        blocked_example: ProbeResult | None = None
        for payload in payloads:
            result = await self.s.probe(
                point=point, payload=payload, marker=marker,
                vuln_class=self.vuln_class, module=self.name,
            )
            if result is None:
                break  # payload budget exhausted
            if result.verdict.verdict == "executed" and result.verdict.confidence >= 0.7:
                self._record(result, oracle=oracle)
                return result
            if result.verdict.verdict == "blocked":
                blocked_example = result

        # The Brain adapts around a filter using its evasion-transform library
        # (plus LLM variants when available) to map the target's WAF coverage.
        if blocked_example is not None:
            variants = await self.s.brain.evade(
                vuln_class=self.vuln_class, marker=marker,
                payload=blocked_example.payload,
                evidence=blocked_example.response.text[:400],
            )
            for payload in variants:
                result = await self.s.probe(
                    point=point, payload=payload, marker=marker,
                    vuln_class=self.vuln_class, module=self.name,
                )
                if result is None:
                    break
                if result.verdict.verdict == "executed" and result.verdict.confidence >= 0.7:
                    self._record(result, oracle=oracle, ai_assisted=True)
                    return result
        return None

    async def plan(self, *, marker: str = "", host: str = "", sleep: int = 6,
                   context: str = "", oracle: str | None = None,
                   limit: int = 40) -> list[str]:
        """Ask the Brain to plan payloads for this module's class + context."""
        return await self.s.brain.plan(
            vuln_class=self.vuln_class, marker=marker, host=host, sleep=sleep,
            context=context, oracle=oracle, limit=limit,
        )

    def _record(self, result: ProbeResult, *, oracle: str,
                ai_assisted: bool = False,
                confidence: Confidence = Confidence.CONFIRMED) -> Finding:
        v = result.verdict
        point = result.injection_point
        finding = Finding(
            vuln_class=self.vuln_class,
            module=self.name,
            injection_point=point.describe(),
            url=point.target.url,
            method=point.target.method,
            payload=result.payload,
            severity=self.severity,
            confidence=confidence,
            marker=result.marker,
            evidence=(v.evidence or "")[:500],
            oracle=oracle,
            response_status=result.response.status,
            remediation=self.remediation,
            ai_signal=(("ai-adapted; " if ai_assisted else "") + v.signal)[:300],
            request_summary=f"{point.target.method} {point.target.url} [{point.describe()}]",
        )
        self.s.record(finding)
        return finding
