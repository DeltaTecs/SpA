"""Registry of available analysis task types.

Tasks register themselves at import time via the :func:`register` class
decorator. The job runner and HTTP layer look tasks up by ``task_type`` and never
import a concrete task, so the set of analyses can grow without touching them.
"""

from __future__ import annotations

from typing import Dict, List

from .base import AnalysisTask

_REGISTRY: Dict[str, AnalysisTask] = {}


def register(cls):
    """Class decorator: instantiate ``cls`` and register the singleton instance."""
    task = cls()
    if not task.task_type or task.task_type == "base":
        raise ValueError(f"{cls.__name__} must define a unique task_type.")
    if task.task_type in _REGISTRY:
        raise ValueError(f"Duplicate task_type '{task.task_type}'.")
    _REGISTRY[task.task_type] = task
    return cls


def get(task_type: str) -> AnalysisTask:
    """Return the registered task, or raise ``KeyError`` with the known types."""
    try:
        return _REGISTRY[task_type]
    except KeyError:
        known = ", ".join(sorted(_REGISTRY)) or "<none>"
        raise KeyError(f"Unknown task_type '{task_type}'. Available: {known}.")


def available() -> List[AnalysisTask]:
    """All registered tasks, ordered by task_type for a stable UI listing."""
    return [_REGISTRY[name] for name in sorted(_REGISTRY)]
