"""Test that the post-exploitation channel derives from a finding correctly."""

import asyncio

from voidstrike.ai import AIEngine, Analyzer
from voidstrike.authorization import Engagement, ScopeGuard
from voidstrike.config import Config
from voidstrike.engine.models import Confidence, Finding, InjectionPoint, Severity, Target
from voidstrike.engine.session import Session
from voidstrike.http_client import HttpClient
from voidstrike.oob import OOBManager
from voidstrike.shell.channel import ChannelError, RCEChannel

from .mockserver import MockServer


def _guard():
    g = ScopeGuard(Engagement(name="c", in_scope=["127.0.0.1"]), resolve_dns=False)
    g.grant_consent()
    return g


def test_channel_runs_commands():
    with MockServer() as srv:
        marker = "VSXTESTMARKERZ"
        target = Target(url=f"{srv.base}/ping", method="GET", params={"host": "1"})
        point = InjectionPoint(target, "query", "host", "1")
        finding = Finding(
            vuln_class="OS Command Injection", module="cmd_injection",
            injection_point="query:host", url=target.url, method="GET",
            payload=f"; echo {marker}", severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED, marker=marker, oracle="output",
        )

        config = Config()
        config.ai.enabled = False

        async def _go():
            async with HttpClient(config.http, _guard()) as http:
                session = Session(config, http, Analyzer(AIEngine(config.ai)),
                                  OOBManager(config.oob))
                channel = RCEChannel(session, point, finding)
                assert await channel.check() is True
                out = await channel.run("id")
                return out

        out = asyncio.run(_go())
    assert "www-data" in out


def test_channel_rejects_oob_finding():
    target = Target(url="http://127.0.0.1/x")
    point = InjectionPoint(target, "query", "q", "")
    finding = Finding(
        vuln_class="x", module="cmd_injection", injection_point="query:q",
        url=target.url, method="GET", payload="`nslookup x`", marker="",
        oracle="oob",
    )
    config = Config()
    session = Session(config, None, Analyzer(AIEngine(config.ai)), OOBManager(config.oob))
    try:
        RCEChannel(session, point, finding)
    except ChannelError:
        return
    raise AssertionError("expected ChannelError for an OOB-only finding")
