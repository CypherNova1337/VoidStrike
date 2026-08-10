"""Shared session state and the low-level probe primitive.

A :class:`Session` bundles the configured HTTP client, scope guard, OOB
manager, the offensive :class:`~voidstrike.ai.brain.Brain` and accumulated
findings, and exposes :meth:`probe` — the single primitive every detection
module uses to send one payload at one injection point and get back a normalized
result (response + verdict + timing).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..ai.brain import Brain, Verdict
from ..config import Config
from ..http_client import HttpClient, Response
from ..oob import OOBManager
from ..utils.logging import get_logger
from .models import Finding, InjectionPoint, Target


@dataclass
class ProbeResult:
    injection_point: InjectionPoint
    payload: str
    marker: str
    response: Response
    verdict: Verdict
    elapsed: float


class Session:
    def __init__(self, config: Config, http: HttpClient, brain: Brain,
                 oob: OOBManager, logger=None):
        self.config = config
        self.http = http
        self.brain = brain
        self.oob = oob
        self.log = logger or get_logger(use_color=config.use_color)
        self.findings: list[Finding] = []
        self._baselines: dict[str, float] = {}
        self._payload_counts: dict[str, int] = {}

    # -- baselines -------------------------------------------------------
    async def baseline(self, point: InjectionPoint) -> float:
        key = point.target.url
        if key in self._baselines:
            return self._baselines[key]
        samples = []
        for _ in range(2):
            r = await self._send(point, point.baseline_value or "1")
            if r.ok:
                samples.append(r.elapsed)
        value = min(samples) if samples else 0.0
        self._baselines[key] = value
        return value

    # -- probing ---------------------------------------------------------
    def _budget_ok(self, module: str, point: InjectionPoint) -> bool:
        key = f"{module}:{point.target.url}:{point.describe()}"
        count = self._payload_counts.get(key, 0)
        if count >= self.config.max_payloads_per_module:
            return False
        self._payload_counts[key] = count + 1
        return True

    async def probe(self, *, point: InjectionPoint, payload: str, marker: str,
                    vuln_class: str, module: str) -> ProbeResult | None:
        """Send one payload and evaluate it. Returns None if budget exceeded."""
        if not self._budget_ok(module, point):
            return None
        baseline = await self.baseline(point)
        start = time.monotonic()
        resp = await self._send(point, payload)
        elapsed = time.monotonic() - start
        verdict = await self.brain.assess(
            vuln_class=vuln_class, marker=marker, payload=payload,
            status=resp.status, snippet=resp.text[:4000], elapsed=elapsed,
            baseline=baseline,
        )
        return ProbeResult(point, payload, marker, resp, verdict, elapsed)

    async def _send(self, point: InjectionPoint, value: str) -> Response:
        t = point.target
        params = dict(t.params)
        body = dict(t.body_params)
        headers = dict(t.headers)
        json_body = dict(t.json_body) if t.json_body else None

        if point.location == "query":
            params[point.name] = value
        elif point.location == "body":
            body[point.name] = value
        elif point.location == "header":
            headers[point.name] = value
        elif point.location == "json" and json_body is not None:
            json_body[point.name] = value

        return await self.http.request(
            t.method, t.url,
            params=params or None,
            data=body or None if json_body is None else None,
            json=json_body,
            headers=headers or None,
        )

    # -- findings --------------------------------------------------------
    def record(self, finding: Finding) -> None:
        self.findings.append(finding)
        self.log.success(
            f"[{finding.vuln_class}] {finding.confidence.value.upper()} at "
            f"{finding.injection_point} via {finding.oracle} oracle "
            f"({finding.url})"
        )
