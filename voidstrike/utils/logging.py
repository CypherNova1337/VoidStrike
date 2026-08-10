"""Structured, colorized logging for VoidStrike."""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone

from ..banner import RESET, DIM, RED, GREEN, YELLOW, CYAN, MAGENTA, BOLD

_LEVEL_COLORS = {
    "DEBUG": DIM,
    "INFO": CYAN,
    "SUCCESS": GREEN,
    "WARNING": YELLOW,
    "ERROR": RED,
    "CRITICAL": BOLD + RED,
}

SUCCESS_LEVEL = 25
logging.addLevelName(SUCCESS_LEVEL, "SUCCESS")


def _success(self, message, *args, **kwargs):  # pragma: no cover - thin shim
    if self.isEnabledFor(SUCCESS_LEVEL):
        self._log(SUCCESS_LEVEL, message, args, **kwargs)


logging.Logger.success = _success  # type: ignore[attr-defined]


class _ColorFormatter(logging.Formatter):
    def __init__(self, use_color: bool = True):
        super().__init__()
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        level = record.levelname
        msg = record.getMessage()
        if self.use_color:
            color = _LEVEL_COLORS.get(level, "")
            tag = f"{color}{level:<8}{RESET}"
            ts_str = f"{DIM}{ts}{RESET}"
        else:
            tag = f"{level:<8}"
            ts_str = ts
        return f"{ts_str} {tag} {msg}"


def get_logger(name: str = "voidstrike", *, level: int = logging.INFO,
               use_color: bool = True) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(_ColorFormatter(use_color=use_color))
        logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    return logger
