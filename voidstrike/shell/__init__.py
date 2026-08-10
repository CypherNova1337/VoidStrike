"""Post-exploitation: turn a confirmed injection into a command channel."""

from .channel import RCEChannel
from .interactive import InteractiveShell

__all__ = ["RCEChannel", "InteractiveShell"]
