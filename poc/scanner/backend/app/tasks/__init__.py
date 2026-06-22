"""Analysis task types and their registry.

Importing this package registers the built-in tasks (their modules call
:func:`register` at import time), so ``available()``/``get()`` see them.
"""

from __future__ import annotations

from .base import AnalysisTask, build_default_toolsets
from .registry import available, get, register

# Import built-in task modules for their registration side effects.
from . import vulnerability_checks  # noqa: F401,E402  (registers "vulnerability_checks")

__all__ = ["AnalysisTask", "build_default_toolsets", "available", "get", "register"]
