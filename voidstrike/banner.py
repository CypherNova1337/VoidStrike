"""Terminal banners and the mandatory authorized-use notice."""

from __future__ import annotations

from . import __version__

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
MAGENTA = "\033[35m"

_ART = r"""
 __     __     _     _ ____  _        _ _
 \ \   / /__  (_) __| / ___|| |_ _ __(_) | _____
  \ \ / / _ \ | |/ _` \___ \| __| '__| | |/ / _ \
   \ V / (_) || | (_| |___) | |_| |  | |   <  __/
    \_/ \___/_/ |\__,_|____/ \__|_|  |_|_|\_\___|
            |__/
"""

LEGAL_NOTICE = (
    "Only use this on authorized targets. Unauthorized testing is illegal."
)


def color(text: str, code: str, enabled: bool = True) -> str:
    if not enabled:
        return text
    return f"{code}{text}{RESET}"


def render_banner(use_color: bool = True) -> str:
    """Return the startup banner with version and project attribution."""
    lines = []
    lines.append(color(_ART, MAGENTA, use_color))
    lines.append(
        color(f"  VoidStrike v{__version__}", BOLD + CYAN, use_color)
        + color("  —  AI-assisted RCE testing framework", DIM, use_color)
    )
    lines.append(color("  A VoidSec-Hub project", DIM, use_color))
    lines.append("")
    lines.append(color("  " + "=" * 68, DIM, use_color))
    lines.append(color("  !! AUTHORIZED SECURITY TESTING ONLY !!", BOLD + RED, use_color))
    lines.append(color("  " + "=" * 68, DIM, use_color))
    return "\n".join(lines)


def render_legal(use_color: bool = True) -> str:
    return color(LEGAL_NOTICE, YELLOW, use_color)
