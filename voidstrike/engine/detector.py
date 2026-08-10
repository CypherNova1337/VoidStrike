"""Detection orchestrator.

The :class:`Detector` wires together the scope guard, HTTP client, OOB manager
and AI analyzer, then runs the selected modules across each target, collecting
findings into a :class:`~voidstrike.reporting.report.Report`.
"""

from __future__ import annotations

from ..ai import AIEngine, Analyzer
from ..authorization import ScopeGuard
from ..config import Config
from ..http_client import HttpClient
from ..oob import OOBManager
from ..reporting import Report
from ..utils.logging import get_logger
from .models import Target
from .session import Session


class Detector:
    def __init__(self, config: Config, guard: ScopeGuard, *,
                 module_names: list[str] | None = None):
        self.config = config
        self.guard = guard
        self.module_names = module_names
        self.log = get_logger(use_color=config.use_color,
                              level=10 if config.verbose else 20)

    async def run(self, targets: list[Target]) -> Report:
        from ..modules import all_modules, get_module

        ai_engine = AIEngine(self.config.ai)
        analyzer = Analyzer(ai_engine)
        oob = OOBManager(self.config.oob)
        report = Report(self.guard.engagement, ai_status=ai_engine.status)

        if self.module_names:
            module_classes = [m for m in (get_module(n) for n in self.module_names) if m]
            missing = set(self.module_names) - {m.name for m in module_classes}
            for name in missing:
                self.log.warning(f"unknown module ignored: {name}")
        else:
            module_classes = all_modules()

        self.log.info(
            f"Loaded {len(module_classes)} module(s): "
            + ", ".join(m.name for m in module_classes)
        )
        self.log.info(f"AI assistance: {ai_engine.status}")

        await oob.start()
        try:
            async with HttpClient(self.config.http, self.guard) as http:
                session = Session(self.config, http, analyzer, oob, self.log)
                for target in targets:
                    # Scope is enforced per-request too, but fail fast here.
                    if not self.guard.is_allowed(target.url):
                        self.log.warning(f"skipping out-of-scope target: {target.url}")
                        continue
                    report.targets_tested += 1
                    self.log.info(f"Testing {target.method} {target.url}")
                    for cls in module_classes:
                        module = cls(session)
                        try:
                            await module.run(target)
                        except Exception as exc:  # noqa: BLE001 - isolate module failures
                            self.log.error(f"module {cls.name} error on "
                                           f"{target.url}: {exc}")
                report.findings = session.findings
                report.requests_sent = http.stats.get("sent", 0)

                if analyzer.engine.available and session.findings:
                    summary = "; ".join(
                        f"{f.vuln_class} at {f.injection_point}" for f in session.findings
                    )
                    report.ai_recommendation = await analyzer.recommend_next(summary)
        finally:
            await oob.stop()

        return report.finalize()
