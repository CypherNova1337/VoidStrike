"""The Brain — VoidStrike's central offensive intelligence.

The Brain is not an optional add-on; it drives every engagement. It reasons over
the built-in knowledge base (:mod:`voidstrike.ai.knowledge`) to *plan* which
manoeuvres to try, *assess* whether a payload executed, and *adapt* around
filters. When an LLM endpoint is configured it layers live reasoning on top of
that expertise (grounded in the same corpus); when it isn't, the Brain still
operates as a deterministic expert system. Either way it is always "on".

The one thing the Brain will not do is invent success: an "executed" verdict
must be corroborated by a real oracle (marker echoed, timing, or OOB callback),
never by model confidence alone.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import knowledge as kb
from . import prompts
from .engine import AIEngine


@dataclass
class Verdict:
    verdict: str  # executed | reflected | blocked | inconclusive
    confidence: float
    signal: str
    evidence: str | None = None
    source: str = "expert"  # "expert" | "llm"


class Brain:
    def __init__(self, engine: AIEngine):
        self.engine = engine
        self.reasoning: list[str] = []

    # -- identity --------------------------------------------------------
    @property
    def augmented(self) -> bool:
        """True when a live LLM is reasoning alongside the expert core."""
        return self.engine.available

    @property
    def mode(self) -> str:
        return "expert+llm" if self.augmented else "expert"

    def _log(self, msg: str) -> None:
        self.reasoning.append(msg)

    # -- planning --------------------------------------------------------
    async def plan(self, *, vuln_class: str, marker: str = "", host: str = "",
                   sleep: int = 6, context: str = "", oracle: str | None = None,
                   limit: int = 40) -> list[str]:
        """Choose an ordered set of payloads for this class + observed context.

        Always starts from the built-in corpus (ranked by context fit), then, if
        an LLM is available, appends model-suggested payloads it hasn't already
        covered.
        """
        techniques = kb.techniques_for(vuln_class, context, oracle)
        payloads = kb.render_payloads(techniques, marker=marker, host=host,
                                      sleep=sleep, limit=limit)
        top = ", ".join(t.name for t in techniques[:3]) or "n/a"
        self._log(f"plan[{vuln_class}] {len(payloads)} payloads; leading manoeuvres: {top}")

        if self.engine.available and marker:
            extra = await self._llm_payloads(vuln_class, marker, context, limit=8)
            new = [p for p in extra if p not in payloads]
            if new:
                self._log(f"llm added {len(new)} context-specific payloads")
                payloads.extend(new)
        return payloads

    async def _llm_payloads(self, vuln_class: str, marker: str, context: str,
                            limit: int) -> list[str]:
        prompt = prompts.SUGGEST_PAYLOADS.format(
            n=limit, vuln_class=vuln_class, marker=marker, context=context[:1500]
        )
        data = await self.engine.complete_json(prompts.SYSTEM, prompt)
        return _string_list(data, limit)

    # -- assessment ------------------------------------------------------
    async def assess(self, *, vuln_class: str, marker: str, payload: str,
                     status: int, snippet: str, elapsed: float,
                     baseline: float) -> Verdict:
        base = self._expert_verdict(marker, status, snippet, elapsed, baseline)
        if not self.engine.available:
            return base

        prompt = prompts.ANALYZE_RESPONSE.format(
            vuln_class=vuln_class, marker=marker, payload=payload, status=status,
            elapsed=elapsed, baseline=baseline, snippet=snippet[:1500],
        )
        data = await self.engine.complete_json(prompts.SYSTEM, prompt)
        if not isinstance(data, dict) or "verdict" not in data:
            return base
        try:
            llm = Verdict(
                verdict=str(data.get("verdict", "inconclusive")).lower(),
                confidence=float(data.get("confidence", 0.5)),
                signal=str(data.get("signal", "")),
                evidence=data.get("evidence"),
                source="llm",
            )
        except (TypeError, ValueError):
            return base
        # Guardrail: never let the model manufacture an unproven "executed".
        if llm.verdict == "executed" and marker and marker not in snippet:
            if base.verdict != "executed":
                llm.confidence = min(llm.confidence, 0.55)
        return llm if llm.confidence >= base.confidence else base

    @staticmethod
    def _expert_verdict(marker: str, status: int, snippet: str, elapsed: float,
                        baseline: float) -> Verdict:
        if marker and marker in snippet:
            return Verdict("executed", 0.97, "success marker reflected in response",
                           evidence=marker)
        if baseline > 0 and elapsed >= baseline + 4.0:
            return Verdict("inconclusive", 0.6,
                           f"response delayed {elapsed - baseline:.1f}s over baseline "
                           "(possible time-based execution)")
        low = snippet.lower()
        blocked = ("waf", "forbidden", "blocked", "not acceptable", "access denied",
                   "request rejected", "mod_security")
        if status in (403, 406, 501) or any(s in low for s in blocked):
            return Verdict("blocked", 0.6, f"filter/WAF indicator (status {status})")
        return Verdict("inconclusive", 0.3, "no execution marker observed")

    # -- adaptation ------------------------------------------------------
    async def evade(self, *, vuln_class: str, marker: str, payload: str,
                    evidence: str = "", limit: int = 8) -> list[str]:
        """Produce filter-evasion variants: transform library first, LLM after."""
        variants = kb.apply_evasions(payload)
        if variants:
            self._log(f"evade: {len(variants)} transform-library variants")
        if self.engine.available:
            prompt = prompts.ADAPT_WAF.format(
                vuln_class=vuln_class, marker=marker, payload=payload,
                evidence=evidence[:600], n=limit,
            )
            data = await self.engine.complete_json(prompts.SYSTEM, prompt)
            for p in _string_list(data, limit):
                if p not in variants:
                    variants.append(p)
        return variants[:limit]

    # -- strategy --------------------------------------------------------
    async def recommend_next(self, summary: str, findings: int) -> str:
        if self.engine.available:
            out = await self.engine.complete(
                prompts.SYSTEM, prompts.RECOMMEND_NEXT.format(summary=summary[:2000])
            )
            if out:
                return out.strip()
        # Deterministic expert fallback.
        if findings:
            return ("Establish a command channel on the confirmed injection "
                    "(`voidstrike shell`), then enumerate privileges and pivot "
                    "targets — all within your authorized scope.")
        return ("No RCE confirmed yet. Widen the input surface: test POST bodies, "
                "JSON fields and headers (--test-headers), and enable OOB "
                "(--oob-domain) to catch blind execution.")

    def knows(self, vuln_class: str) -> str:
        techs = [t for t in kb.TECHNIQUES if t.vuln_class == vuln_class]
        return f"{len(techs)} manoeuvres: " + ", ".join(t.name for t in techs)


def _string_list(data, limit: int) -> list[str]:
    if isinstance(data, list):
        return [str(x) for x in data if isinstance(x, (str, int, float))][:limit]
    if isinstance(data, dict):
        for key in ("payloads", "variants", "items", "results"):
            if isinstance(data.get(key), list):
                return [str(x) for x in data[key]][:limit]
    return []
