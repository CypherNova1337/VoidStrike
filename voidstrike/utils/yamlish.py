"""Minimal YAML loading for VoidStrike's small config/target files.

Prefers PyYAML when installed; otherwise parses the small subset of YAML used by
the example files (scalars and simple string lists), so VoidStrike keeps working
with no third-party dependencies.
"""

from __future__ import annotations


def load_yaml(text: str) -> dict:
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
            data[key] = [] if value == "" else _coerce(value)
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
