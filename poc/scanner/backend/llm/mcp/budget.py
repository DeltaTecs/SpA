"""A thread-safe call budget for capping billable tool calls.

A :class:`CallBudget` bounds how many times a (typically paid) tool may be
dispatched within some scope - e.g. one analysis job. It is deliberately tiny
and decoupled from any toolset so it can be shared by the concurrent workers of
a single job and consulted by :class:`llm.mcp.wrappers.BudgetToolset`.
"""

from __future__ import annotations

import threading


class CallBudget:
    """A thread-safe counter that caps how many calls may be made.

    ``limit`` is the maximum number of calls allowed; a non-positive ``limit``
    means *unlimited*. :meth:`try_consume` atomically reserves one unit,
    returning ``True`` while budget remains and ``False`` once exhausted.
    """

    def __init__(self, limit: int = 0) -> None:
        self._limit = limit
        self._used = 0
        self._lock = threading.Lock()

    @property
    def unlimited(self) -> bool:
        return self._limit <= 0

    def try_consume(self) -> bool:
        """Reserve one unit of budget; ``True`` if granted, ``False`` if spent."""
        if self.unlimited:
            return True
        with self._lock:
            if self._used >= self._limit:
                return False
            self._used += 1
            return True

    @property
    def used(self) -> int:
        with self._lock:
            return self._used

    @property
    def limit(self) -> int:
        return self._limit
