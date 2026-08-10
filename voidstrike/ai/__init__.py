"""AI core for VoidStrike — an always-on offensive brain with built-in expertise."""

from .engine import AIEngine
from .brain import Brain, Verdict
from .analyzer import Analyzer  # backward-compat alias for Brain
from . import knowledge

__all__ = ["AIEngine", "Brain", "Analyzer", "Verdict", "knowledge"]
