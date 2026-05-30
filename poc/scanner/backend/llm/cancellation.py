"""Cooperative cancellation for long-running LLM runs.

A :class:`CancellationToken` lets an external caller (e.g. an HTTP "terminate"
request handled on another thread) ask an in-flight :meth:`McpLlmClient.run`
to stop at the next safe point. The token wraps a :class:`threading.Event`, so
setting it from another thread is safe; the run loop polls it between LLM turns
and before each tool call and raises :class:`OperationCancelled` when it is set.

The token only stops *new* work cooperatively — it cannot interrupt a tool call
that is already blocked inside an MCP server. Killing the underlying tool
processes (so the blocked call returns promptly) is the responsibility of the
caller; once it returns, the next poll observes the token and stops the loop.
"""

from __future__ import annotations

import threading


class OperationCancelled(Exception):
    """Raised inside a run loop once its :class:`CancellationToken` is set."""


class CancellationToken:
    """A thread-safe, one-way "please stop" flag shared with a run loop."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        """Request cancellation. Idempotent and safe to call from any thread."""
        self._event.set()

    @property
    def is_cancelled(self) -> bool:
        return self._event.is_set()

    def raise_if_cancelled(self) -> None:
        """Raise :class:`OperationCancelled` if cancellation has been requested."""
        if self._event.is_set():
            raise OperationCancelled()
