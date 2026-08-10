"""Backward-compatibility shim.

The response-analysis role has been absorbed into the always-on
:class:`~voidstrike.ai.brain.Brain`. ``Analyzer`` remains as an alias so older
imports keep working.
"""

from __future__ import annotations

from .brain import Brain, Verdict

# Historical name — the Brain now owns analysis, planning and adaptation.
Analyzer = Brain

__all__ = ["Analyzer", "Brain", "Verdict"]
