"""End-to-end detection test against the local mock vulnerable server."""

import asyncio

from voidstrike.config import Config
from voidstrike.engine.detector import Detector
from voidstrike.targets import target_from_url

from .mockserver import MockServer


def test_detects_command_injection():
    with MockServer() as srv:
        target = target_from_url(f"{srv.base}/ping?host=127.0.0.1")
        config = Config()
        config.ai.enabled = False
        config.use_color = False
        config.http.requests_per_second = 1000
        detector = Detector(config, module_names=["cmd_injection"])
        report = asyncio.run(detector.run([target]))

    assert report.targets_tested == 1
    assert any(f.module == "cmd_injection" for f in report.findings), (
        "expected a command-injection finding from the mock server"
    )
    finding = next(f for f in report.findings if f.module == "cmd_injection")
    assert finding.oracle == "output"
    assert finding.marker and finding.marker in finding.evidence
