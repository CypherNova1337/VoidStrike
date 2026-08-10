"""High-level AI helpers layered on top of :class:`AIEngine`.

Every method degrades gracefully: when no LLM is configured it falls back to
deterministic heuristics so VoidStrike remains fully functional offline. The
AI, when present, sharpens verdicts and expands payload coverage — it never
becomes a hard dependency.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import prompts
from .engine import AIEngine


@dataclass
class Verdict:
    verdict: str  # executed | reflected | blocked | inconclusive
    confidence: float
    signal: str
    evidence: str | None = None
    source: str = "heuristic"  # "heuristic" | "ai"


class Analyzer:
    def __init__(self, engine: AIEngine):
        self.engine = engine

    async def analyze_response(self, *, vuln_class: str, marker: str, payload: str,
                               status: int, snippet: str, elapsed: float,
                               baseline: float) -> Verdict:
        # Deterministic first pass — cheap and reliable.
        base = self._heuristic_verdict(marker, status, snippet, elapsed, baseline)
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
            ai = Verdict(
                verdict=str(data.get("verdict", "inconclusive")).lower(),
                confidence=float(data.get("confidence", 0.5)),
                signal=str(data.get("signal", "")),
                evidence=data.get("evidence"),
                source="ai",
            )
        except (TypeError, ValueError):
            return base
        # Trust a high-confidence "executed" only if the marker is actually present
        # or timing corroborates it — the AI must not manufacture success.
        if ai.verdict == "executed" and marker not in snippet:
            if base.verdict != "executed":
                ai.confidence = min(ai.confidence, 0.55)
        return ai if ai.confidence >= base.confidence else base

    async def suggest_payloads(self, *, vuln_class: str, marker: str, context: str,
                               n: int = 8) -> list[str]:
        if not self.engine.available:
            return []
        prompt = prompts.SUGGEST_PAYLOADS.format(
            n=n, vuln_class=vuln_class, marker=marker, context=context[:1500]
        )
        data = await self.engine.complete_json(prompts.SYSTEM, prompt)
        return _string_list(data, limit=n)

    async def adapt_to_filter(self, *, vuln_class: str, marker: str, payload: str,
                              evidence: str, n: int = 6) -> list[str]:
        if not self.engine.available:
            return []
        prompt = prompts.ADAPT_WAF.format(
            vuln_class=vuln_class, marker=marker, payload=payload,
            evidence=evidence[:600], n=n,
        )
        data = await self.engine.complete_json(prompts.SYSTEM, prompt)
        return _string_list(data, limit=n)

    async def recommend_next(self, summary: str) -> str:
        if not self.engine.available:
            return ""
        return await self.engine.complete(
            prompts.SYSTEM, prompts.RECOMMEND_NEXT.format(summary=summary[:2000])
        )

    # -- heuristics ------------------------------------------------------
    @staticmethod
    def _heuristic_verdict(marker: str, status: int, snippet: str, elapsed: float,
                           baseline: float) -> Verdict:
        if marker and marker in snippet:
            return Verdict("executed", 0.97, "success marker reflected in response",
                           evidence=marker)
        # Timing oracle: response markedly slower than baseline suggests a sleep ran.
        if baseline > 0 and elapsed >= baseline + 4.0:
            return Verdict("inconclusive", 0.6,
                           f"response delayed {elapsed - baseline:.1f}s over baseline "
                           "(possible time-based execution)")
        blocked_signals = ("waf", "forbidden", "blocked", "not acceptable", "access denied")
        low = snippet.lower()
        if status in (403, 406, 501) or any(s in low for s in blocked_signals):
            return Verdict("blocked", 0.6, f"filter/WAF indicator (status {status})")
        return Verdict("inconclusive", 0.3, "no execution marker observed")


def _string_list(data, limit: int) -> list[str]:
    if isinstance(data, list):
        out = [str(x) for x in data if isinstance(x, (str, int, float))]
        return out[:limit]
    if isinstance(data, dict):
        for key in ("payloads", "variants", "items", "results"):
            if isinstance(data.get(key), list):
                return [str(x) for x in data[key]][:limit]
    return []
