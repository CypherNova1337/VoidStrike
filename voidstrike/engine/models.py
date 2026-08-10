"""Core data models shared across the engine and modules."""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field, asdict
from enum import Enum


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    TENTATIVE = "tentative"
    FIRM = "firm"
    CONFIRMED = "confirmed"


@dataclass
class Target:
    """A single request template describing where user input lands."""

    url: str
    method: str = "GET"
    # Parameter name -> baseline value. Each is fuzzed independently.
    params: dict[str, str] = field(default_factory=dict)
    body_params: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    # Header names to treat as injection points (e.g. "User-Agent", "X-Forwarded-For").
    header_injection: list[str] = field(default_factory=list)
    # JSON body template; values equal to "*" mark injection points.
    json_body: dict | None = None
    # -- file-upload testing (optional) --
    #: multipart field name that accepts a file upload.
    upload_field: str = ""
    #: extra multipart form fields to send alongside the file.
    upload_extra: dict[str, str] = field(default_factory=dict)
    #: candidate base URLs where an uploaded file may become web-accessible,
    #: e.g. ["https://host/uploads/"]. "{name}" is substituted with the filename.
    upload_url_bases: list[str] = field(default_factory=list)

    def injection_points(self) -> list["InjectionPoint"]:
        points: list[InjectionPoint] = []
        for name, val in self.params.items():
            points.append(InjectionPoint(self, "query", name, val))
        for name, val in self.body_params.items():
            points.append(InjectionPoint(self, "body", name, val))
        for name in self.header_injection:
            points.append(InjectionPoint(self, "header", name, self.headers.get(name, "")))
        if self.json_body:
            for name, val in self.json_body.items():
                if val == "*":
                    points.append(InjectionPoint(self, "json", name, ""))
        return points


@dataclass
class InjectionPoint:
    target: Target
    location: str  # query | body | header | json
    name: str
    baseline_value: str = ""

    def describe(self) -> str:
        return f"{self.location}:{self.name}"


@dataclass
class Finding:
    vuln_class: str
    module: str
    injection_point: str
    url: str
    method: str
    payload: str
    severity: Severity = Severity.HIGH
    confidence: Confidence = Confidence.FIRM
    marker: str = ""
    evidence: str = ""
    oracle: str = ""  # "output" | "time" | "oob"
    request_summary: str = ""
    response_status: int = 0
    remediation: str = ""
    ai_signal: str = ""
    discovered_at: float = field(default_factory=time.time)
    finding_id: str = field(default_factory=lambda: secrets.token_hex(4))

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        return d


def new_marker() -> str:
    """A unique, low-collision success marker for output-based oracles."""
    return f"VSX{secrets.token_hex(5).upper()}Z"
