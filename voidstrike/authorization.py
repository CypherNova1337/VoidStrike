"""Authorization and scope enforcement.

Every active operation in VoidStrike must pass through :class:`ScopeGuard`.
The guard refuses to touch any host that is not explicitly listed in the
engagement scope, and it records an auditable consent decision before any
payload is sent. This is the single most important safety control in the
framework — it is intentionally strict and fails closed.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import os
import socket
import time
from dataclasses import dataclass, field, asdict
from typing import Iterable
from urllib.parse import urlparse


class ScopeViolation(RuntimeError):
    """Raised when an operation targets a host outside the authorized scope."""


class AuthorizationError(RuntimeError):
    """Raised when the engagement has not been properly authorized."""


# Hosts that must never be targeted, regardless of scope configuration.
# These protect against typos that would aim the tool at infrastructure the
# operator almost certainly does not own.
_HARD_BLOCKLIST = {
    "localhost.localdomain",
}
_BLOCKED_SUFFIXES = (
    ".gov",
    ".mil",
    ".int",
)


@dataclass
class Engagement:
    """Describes an authorized penetration-testing engagement."""

    name: str
    authorized_by: str = ""
    reference: str = ""  # ticket / contract / rules-of-engagement id
    # Hostname globs (e.g. "*.example.com") and/or CIDR ranges that are in scope.
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    # Optional hard expiry (unix epoch seconds). 0 == no expiry.
    expires_at: float = 0.0
    allow_private_ranges: bool = True
    notes: str = ""

    @classmethod
    def from_file(cls, path: str) -> "Engagement":
        with open(path, "r", encoding="utf-8") as fh:
            if path.endswith((".yaml", ".yml")):
                data = _load_yaml(fh.read())
            else:
                data = json.load(fh)
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        clean = {k: v for k, v in data.items() if k in known}
        return cls(**clean)

    def to_dict(self) -> dict:
        return asdict(self)


class ScopeGuard:
    """Enforces engagement scope and consent for every active target."""

    def __init__(self, engagement: Engagement, *, consented: bool = False,
                 resolve_dns: bool = True):
        self.engagement = engagement
        self._consented = consented
        self._resolve_dns = resolve_dns
        self._decisions: list[dict] = []

    # -- consent ---------------------------------------------------------
    def grant_consent(self, operator: str = "") -> None:
        """Record that the operator has affirmed they are authorized."""
        self._consented = True
        self._decisions.append(
            {"ts": time.time(), "event": "consent", "operator": operator}
        )

    def require_consent(self) -> None:
        if not self._consented:
            raise AuthorizationError(
                "No authorization on record. You must confirm you are permitted "
                "to test the configured targets before VoidStrike will send any "
                "payloads. Re-run with --i-am-authorized or call "
                "ScopeGuard.grant_consent()."
            )
        if self.engagement.expires_at and time.time() > self.engagement.expires_at:
            raise AuthorizationError(
                "This engagement's authorization window has expired. Refusing to "
                "continue. Update the rules-of-engagement before testing again."
            )

    # -- scope checks ----------------------------------------------------
    def _host_of(self, target: str) -> str:
        if "://" in target:
            return urlparse(target).hostname or ""
        # bare host[:port]
        return target.split("/")[0].split(":")[0]

    def _hard_blocked(self, host: str) -> bool:
        h = host.lower().rstrip(".")
        if h in _HARD_BLOCKLIST:
            return True
        return any(h.endswith(sfx) for sfx in _BLOCKED_SUFFIXES)

    def _matches(self, host: str, patterns: Iterable[str]) -> bool:
        h = host.lower().rstrip(".")
        candidates = {h}
        # Also test resolved IPs against CIDR patterns.
        ips = self._resolve(h) if self._resolve_dns else []
        for pattern in patterns:
            pattern = pattern.strip().lower()
            if not pattern:
                continue
            if "/" in pattern and _looks_like_cidr(pattern):
                try:
                    net = ipaddress.ip_network(pattern, strict=False)
                except ValueError:
                    continue
                for ip in ips + ([h] if _looks_like_ip(h) else []):
                    try:
                        if ipaddress.ip_address(ip) in net:
                            return True
                    except ValueError:
                        continue
            else:
                if any(fnmatch.fnmatch(c, pattern) for c in candidates):
                    return True
        return False

    def _resolve(self, host: str) -> list[str]:
        if _looks_like_ip(host):
            return [host]
        try:
            infos = socket.getaddrinfo(host, None)
            return sorted({i[4][0] for i in infos})
        except OSError:
            return []

    def check(self, target: str) -> str:
        """Validate a target URL/host. Returns the host on success.

        Raises :class:`ScopeViolation` if the host is not authorized.
        """
        self.require_consent()
        host = self._host_of(target)
        if not host:
            raise ScopeViolation(f"Could not parse a host from target {target!r}.")

        if self._hard_blocked(host):
            self._record(target, host, allowed=False, reason="hard-blocklist")
            raise ScopeViolation(
                f"{host!r} is on the built-in hard blocklist (government/"
                "military/reserved). VoidStrike will not target it."
            )

        if self._matches(host, self.engagement.out_of_scope):
            self._record(target, host, allowed=False, reason="out-of-scope")
            raise ScopeViolation(f"{host!r} is explicitly out of scope.")

        if not self.engagement.in_scope:
            self._record(target, host, allowed=False, reason="empty-scope")
            raise ScopeViolation(
                "Engagement scope is empty. Define in_scope hosts/CIDRs before "
                "testing — VoidStrike refuses to run against an undefined scope."
            )

        if not self._matches(host, self.engagement.in_scope):
            self._record(target, host, allowed=False, reason="not-in-scope")
            raise ScopeViolation(
                f"{host!r} is not covered by the engagement scope. Add it to "
                "in_scope only if you are authorized to test it."
            )

        if not self.engagement.allow_private_ranges and _is_private(host, self._resolve(host)):
            self._record(target, host, allowed=False, reason="private-range")
            raise ScopeViolation(
                f"{host!r} resolves to a private/reserved range and "
                "allow_private_ranges is disabled."
            )

        self._record(target, host, allowed=True, reason="in-scope")
        return host

    def is_allowed(self, target: str) -> bool:
        try:
            self.check(target)
            return True
        except (ScopeViolation, AuthorizationError):
            return False

    # -- audit -----------------------------------------------------------
    def _record(self, target: str, host: str, *, allowed: bool, reason: str) -> None:
        self._decisions.append(
            {
                "ts": time.time(),
                "event": "scope-check",
                "target": target,
                "host": host,
                "allowed": allowed,
                "reason": reason,
            }
        )

    @property
    def audit_log(self) -> list[dict]:
        return list(self._decisions)

    def write_audit(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(
                {"engagement": self.engagement.to_dict(), "decisions": self._decisions},
                fh,
                indent=2,
            )


# -- small helpers -------------------------------------------------------
def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _looks_like_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def _is_private(host: str, ips: list[str]) -> bool:
    checkset = ([host] if _looks_like_ip(host) else []) + ips
    for ip in checkset:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local:
            return True
    return False


def _load_yaml(text: str) -> dict:
    """Minimal YAML loader with a graceful fallback.

    Prefers PyYAML when installed; otherwise parses the small subset of YAML
    used by the example scope files (scalars and simple string lists).
    """
    try:
        import yaml  # type: ignore

        return yaml.safe_load(text) or {}
    except ModuleNotFoundError:
        return _tiny_yaml(text)


def _tiny_yaml(text: str) -> dict:
    data: dict = {}
    current_key: str | None = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        stripped = line.strip()
        if stripped.startswith("- ") and current_key is not None:
            data.setdefault(current_key, [])
            if isinstance(data[current_key], list):
                data[current_key].append(_coerce(stripped[2:].strip()))
            continue
        if ":" in line and not line.startswith((" ", "\t")):
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()
            current_key = key
            if value == "":
                data[key] = []
            else:
                data[key] = _coerce(value)
    return data


def _coerce(value: str):
    value = value.strip().strip('"').strip("'")
    if value.lower() in {"true", "false"}:
        return value.lower() == "true"
    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        return value


def load_engagement(path: str | None) -> Engagement:
    if path and os.path.exists(path):
        return Engagement.from_file(path)
    raise AuthorizationError(
        "No engagement/scope file provided. Create one from scope.example.yaml "
        "and pass it with --scope. VoidStrike will not run without a defined "
        "authorized scope."
    )
