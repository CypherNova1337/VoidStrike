"""Build :class:`Target` request templates from URLs or a targets file."""

from __future__ import annotations

import json
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from .authorization import _load_yaml  # reuse the tiny YAML loader
from .engine.models import Target


def target_from_url(url: str, *, method: str = "GET",
                    extra_params: dict | None = None,
                    headers: dict | None = None,
                    header_injection: list[str] | None = None) -> Target:
    """Create a Target from a URL, treating each query parameter as a point."""
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    if extra_params:
        query.update(extra_params)
    # Clean base URL (query is re-attached per-request by the HTTP client).
    base = urlunsplit((parts.scheme, parts.netloc, parts.path, "", parts.fragment))
    is_get = method.upper() == "GET"
    return Target(
        url=base,
        method=method.upper(),
        params=query if is_get else {},
        body_params={} if is_get else query,
        headers=headers or {},
        header_injection=header_injection or [],
    )


def load_targets(path: str) -> list[Target]:
    """Load a list of targets from a YAML/JSON file.

    File format (YAML or JSON): a top-level ``targets`` list, each entry a
    mapping of Target fields. A bare list is also accepted.
    """
    with open(path, "r", encoding="utf-8") as fh:
        raw = fh.read()
    data = _load_yaml(raw) if path.endswith((".yaml", ".yml")) else json.loads(raw)
    entries = data.get("targets", data) if isinstance(data, dict) else data
    if not isinstance(entries, list):
        raise ValueError("targets file must contain a list of targets")
    known = set(Target.__dataclass_fields__)  # type: ignore[attr-defined]
    out: list[Target] = []
    for entry in entries:
        if isinstance(entry, str):
            out.append(target_from_url(entry))
        elif isinstance(entry, dict):
            clean = {k: v for k, v in entry.items() if k in known}
            out.append(Target(**clean))
    return out


def default_header_injection() -> list[str]:
    """Headers commonly logged/processed and worth testing for injection."""
    return ["User-Agent", "X-Forwarded-For", "Referer", "X-Api-Version"]
