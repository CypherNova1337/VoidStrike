"""Detection modules for VoidStrike.

Each module targets one class of remote-code-execution vulnerability. Modules
are discovered dynamically via :func:`all_modules`, so adding a new module is
as simple as dropping a file in this package that subclasses
:class:`~voidstrike.modules.base.Module`.
"""

from __future__ import annotations

import importlib
import pkgutil

from .base import Module

_CACHE: list[type[Module]] | None = None


def all_modules() -> list[type[Module]]:
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    found: list[type[Module]] = []
    for info in pkgutil.iter_modules(__path__):
        if info.name in {"base"}:
            continue
        mod = importlib.import_module(f"{__name__}.{info.name}")
        for attr in vars(mod).values():
            if (
                isinstance(attr, type)
                and issubclass(attr, Module)
                and attr is not Module
            ):
                found.append(attr)
    found.sort(key=lambda m: m.name)
    _CACHE = found
    return found


def get_module(name: str) -> type[Module] | None:
    for m in all_modules():
        if m.name == name:
            return m
    return None


__all__ = ["Module", "all_modules", "get_module"]
