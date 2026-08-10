"""VoidStrike command-line interface.

Usage is URL-first — point it at a target and go:

    voidstrike "https://target.example/ping?host=127.0.0.1"

An engagement scope file (``--scope``) is optional; supply one when you want
VoidStrike to enforce which hosts it may touch.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

from . import __version__
from .authorization import Engagement, ScopeGuard, ScopeViolation, load_engagement
from .banner import GREEN, RED, RESET, YELLOW, render_banner, render_legal
from .config import Config
from .engine.detector import Detector
from .targets import default_header_injection, load_targets, target_from_url

_COMMANDS = {"scan", "modules", "shell"}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="voidstrike",
        description="VoidStrike — AI-assisted RCE testing framework. "
                    "Only use this on authorized targets; unauthorized testing "
                    "is illegal.",
    )
    p.add_argument("--version", action="version", version=f"VoidStrike {__version__}")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    sub = p.add_subparsers(dest="command")

    # scan
    scan = sub.add_parser("scan", help="scan target URL(s) for RCE")
    scan.add_argument("urls", nargs="*", help="target URL(s); query params become "
                                              "injection points")
    scan.add_argument("-u", "--url", action="append", default=[],
                      help="additional target URL (repeatable)")
    scan.add_argument("-t", "--targets", help="YAML/JSON file describing targets")
    scan.add_argument("-s", "--scope", help="optional engagement/scope file to "
                                            "restrict which hosts may be tested")
    scan.add_argument("-m", "--method", default="GET", help="HTTP method (default GET)")
    scan.add_argument("-M", "--modules", help="comma-separated module ids (default: all)")
    scan.add_argument("--headers", action="append", default=[],
                      help="extra header 'Name: value' (repeatable)")
    scan.add_argument("--test-headers", action="store_true",
                      help="also treat common headers as injection points")
    scan.add_argument("--rps", type=float, default=None, help="max requests per second")
    scan.add_argument("--concurrency", type=int, default=None, help="max concurrent requests")
    scan.add_argument("--timeout", type=float, default=None, help="per-request timeout (s)")
    scan.add_argument("--proxy", default=None, help="HTTP(S) proxy URL (e.g. Burp)")
    scan.add_argument("--insecure", action="store_true", help="disable TLS verification")
    scan.add_argument("--oob-domain", default=None, help="OAST collaborator domain")
    scan.add_argument("--oob-listener", type=int, default=0,
                      help="start a local HTTP callback listener on this port")
    scan.add_argument("--no-ai", action="store_true", help="disable AI assistance")
    scan.add_argument("-o", "--output", default="voidstrike-results",
                      help="output directory for reports")
    scan.add_argument("-v", "--verbose", action="store_true")

    # modules
    sub.add_parser("modules", help="list available detection modules")

    # shell
    shell = sub.add_parser("shell",
                           help="open an interactive command channel from a saved finding")
    shell.add_argument("-r", "--report", required=True, help="JSON report from a prior scan")
    shell.add_argument("-s", "--scope", help="optional engagement/scope file")
    shell.add_argument("--finding", help="finding id (default: first channel-capable)")
    shell.add_argument("--proxy", default=None)
    shell.add_argument("--insecure", action="store_true")

    return p


def _parse_headers(items: list[str]) -> dict:
    headers = {}
    for item in items:
        if ":" in item:
            k, _, v = item.partition(":")
            headers[k.strip()] = v.strip()
    return headers


def _apply_http_overrides(config: Config, args) -> None:
    if getattr(args, "rps", None) is not None:
        config.http.requests_per_second = args.rps
    if getattr(args, "concurrency", None) is not None:
        config.http.max_concurrency = args.concurrency
    if getattr(args, "timeout", None) is not None:
        config.http.timeout = args.timeout
    if getattr(args, "proxy", None):
        config.http.proxy = args.proxy
    if getattr(args, "insecure", False):
        config.http.verify_tls = False


def _make_guard(scope_path: str | None) -> ScopeGuard | None:
    """Build a scope guard only if the operator supplied a scope file."""
    if not scope_path:
        return None
    engagement = load_engagement(scope_path)
    guard = ScopeGuard(engagement)
    guard.grant_consent(operator=os.environ.get("USER", ""))
    return guard


def cmd_modules(args) -> int:
    from .modules import all_modules

    print(render_banner(use_color=not args.no_color))
    print()
    for cls in all_modules():
        c0 = GREEN if not args.no_color else ""
        c1 = RESET if not args.no_color else ""
        print(f"  {c0}{cls.name:<20}{c1} {cls.vuln_class}  [{cls.severity.value}]")
    return 0


def cmd_scan(args) -> int:
    use_color = not args.no_color
    print(render_banner(use_color=use_color))
    print(render_legal(use_color=use_color))
    print()

    guard = _make_guard(args.scope)

    config = Config()
    config.use_color = use_color
    config.verbose = args.verbose
    config.output_dir = args.output
    config.ai.enabled = not args.no_ai
    _apply_http_overrides(config, args)
    if args.oob_domain:
        config.oob.enabled = True
        config.oob.collaborator_domain = args.oob_domain
    if args.oob_listener:
        config.oob.enabled = True
        config.oob.listener_port = args.oob_listener

    headers = _parse_headers(args.headers)
    hdr_inj = default_header_injection() if args.test_headers else []
    targets = []
    for url in [*args.urls, *args.url]:
        targets.append(target_from_url(url, method=args.method, headers=headers,
                                       header_injection=hdr_inj))
    if args.targets:
        targets.extend(load_targets(args.targets))
    if not targets:
        print(f"{RED if use_color else ''}[!] No targets. Pass a URL, e.g. "
              f"voidstrike \"https://host/path?p=1\"{RESET if use_color else ''}")
        return 2

    module_names = [m.strip() for m in args.modules.split(",")] if args.modules else None

    detector = Detector(config, guard, module_names=module_names)
    try:
        report = asyncio.run(detector.run(targets))
    except ScopeViolation as exc:
        print(f"{RED if use_color else ''}[!] Scope violation: {exc}"
              f"{RESET if use_color else ''}")
        return 3

    os.makedirs(config.output_dir, exist_ok=True)
    json_path = os.path.join(config.output_dir, "report.json")
    md_path = os.path.join(config.output_dir, "report.md")
    report.write_json(json_path)
    report.write_markdown(md_path)
    if guard is not None:
        guard.write_audit(os.path.join(config.output_dir, "audit.json"))

    print()
    n = len(report.findings)
    tag = GREEN if (n and use_color) else (YELLOW if use_color else "")
    print(f"{tag}[=] {n} RCE finding(s) confirmed across "
          f"{report.targets_tested} target(s), {report.requests_sent} requests."
          f"{RESET if use_color else ''}")
    if report.ai_recommendation:
        print(f"    Suggested next step: {report.ai_recommendation}")
    print(f"    Reports: {json_path} , {md_path}")
    return 0


def cmd_shell(args) -> int:
    import json

    from .ai import AIEngine, Analyzer
    from .config import Config as _Config
    from .engine.models import Confidence, Finding, InjectionPoint, Severity, Target
    from .engine.session import Session
    from .http_client import HttpClient
    from .oob import OOBManager
    from .shell import InteractiveShell, RCEChannel
    from .shell.channel import ChannelError

    guard = _make_guard(args.scope)

    with open(args.report, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    findings = data.get("findings", [])
    chosen = None
    for f in findings:
        if args.finding and f.get("finding_id") != args.finding:
            continue
        if f.get("oracle") == "output" and f.get("module") in {"cmd_injection",
                                                                "code_injection"}:
            chosen = f
            break
    if not chosen:
        print("[!] No channel-capable finding (output-based cmd/code injection) "
              "in report.")
        return 2

    finding = Finding(
        vuln_class=chosen["vuln_class"], module=chosen["module"],
        injection_point=chosen["injection_point"], url=chosen["url"],
        method=chosen["method"], payload=chosen["payload"],
        severity=Severity(chosen.get("severity", "critical")),
        confidence=Confidence(chosen.get("confidence", "confirmed")),
        marker=chosen.get("marker", ""), oracle=chosen.get("oracle", "output"),
    )
    location, _, name = chosen["injection_point"].partition(":")
    target = Target(url=finding.url, method=finding.method)
    point = InjectionPoint(target, location or "query", name, "")

    config = _Config()
    _apply_http_overrides(config, args)

    async def _go():
        async with HttpClient(config.http, guard) as http:
            session = Session(config, http, Analyzer(AIEngine(config.ai)),
                              OOBManager(config.oob))
            try:
                channel = RCEChannel(session, point, finding)
            except ChannelError as exc:
                print(f"[!] {exc}")
                return
            await InteractiveShell(channel, use_color=not getattr(args, "no_color", False)
                                   ).start()

    asyncio.run(_go())
    return 0


def _inject_default_command(argv: list[str]) -> list[str]:
    """Allow ``voidstrike <url>`` with no explicit subcommand -> implicit scan."""
    argv = list(argv)
    for i, tok in enumerate(argv):
        if tok in ("--no-color",):
            continue
        if tok in ("--version", "-h", "--help"):
            return argv
        if tok in _COMMANDS:
            return argv
        # First real positional and it isn't a command -> default to scan.
        return argv[:i] + ["scan"] + argv[i:]
    return argv


def main(argv: list[str] | None = None) -> int:
    raw = sys.argv[1:] if argv is None else list(argv)
    raw = _inject_default_command(raw)
    parser = build_parser()
    args = parser.parse_args(raw)
    if not getattr(args, "no_color", False):
        args.no_color = getattr(args, "no_color", False)
    try:
        if args.command == "scan":
            return cmd_scan(args)
        if args.command == "modules":
            return cmd_modules(args)
        if args.command == "shell":
            return cmd_shell(args)
    except ScopeViolation as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 3
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
