"""Pluggable response caches for MCP tool calls.

Identical tool invocations (same tool name + arguments) recur across a job and
across re-runs of the same recording. Caching the *flattened text* a tool call
returns avoids re-billing the upstream service (e.g. Tavily web search). Entries
are keyed by a stable hash of (toolset name, tool name, arguments).

Three pieces are provided, all independent of any specific tool or vendor:

* :class:`InMemoryTTLCache` - fast, process-wide, bounded LRU with per-entry TTL.
* :class:`SqliteCache` - persistent local file so hits survive restarts.
* :class:`LayeredCache` - read-through over an ordered list of backends.

Every backend is safe to share across worker threads (each guards its state with
a lock) and never raises on a miss; it returns ``None``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any, Optional, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


def make_cache_key(toolset_name: str, tool_name: str, arguments: dict[str, Any]) -> str:
    """Return a stable hash identifying one tool invocation.

    Arguments are serialised canonically (sorted keys, no insignificant
    whitespace) so semantically identical calls collide regardless of key order.
    Values that are not JSON-serialisable fall back to ``str`` via ``default=str``.
    """

    try:
        canonical = json.dumps(
            arguments, sort_keys=True, separators=(",", ":"), default=str
        )
    except (TypeError, ValueError):  # pragma: no cover - default=str makes this rare
        canonical = repr(arguments)
    raw = f"{toolset_name}\x1f{tool_name}\x1f{canonical}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@runtime_checkable
class CacheBackend(Protocol):
    """The minimal read-through surface a tool-call cache must provide."""

    def get(self, key: str) -> Optional[str]:
        ...

    def set(self, key: str, value: str) -> None:
        ...


class InMemoryTTLCache:
    """Process-wide, bounded LRU cache with a per-entry time-to-live.

    Thread-safe via a single lock (mirrors :class:`app.jobs.store.JobStore`).
    The least-recently-used entry is evicted once ``max_entries`` is exceeded;
    entries older than ``ttl_seconds`` are treated as misses and dropped. A
    non-positive ``ttl_seconds`` disables expiry; a non-positive ``max_entries``
    disables the size bound.
    """

    def __init__(self, *, ttl_seconds: float = 0.0, max_entries: int = 1000) -> None:
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        self._lock = threading.Lock()
        #: key -> (created_at, value), ordered least- to most-recently-used.
        self._entries: "OrderedDict[str, tuple[float, str]]" = OrderedDict()

    def get(self, key: str) -> Optional[str]:
        now = time.time()
        with self._lock:
            item = self._entries.get(key)
            if item is None:
                return None
            created_at, value = item
            if self._ttl > 0 and now - created_at > self._ttl:
                del self._entries[key]
                return None
            self._entries.move_to_end(key)  # now most-recently-used
            return value

    def set(self, key: str, value: str) -> None:
        with self._lock:
            self._entries[key] = (time.time(), value)
            self._entries.move_to_end(key)
            if self._max_entries > 0:
                while len(self._entries) > self._max_entries:
                    self._entries.popitem(last=False)  # evict least-recently-used


class SqliteCache:
    """Persistent cache backed by a local SQLite file.

    Survives process restarts so repeated research across runs is not re-billed.
    A single connection (``check_same_thread=False``) is guarded by a lock; the
    table is created on first use and WAL mode keeps concurrent reads cheap. A
    non-positive ``ttl_seconds`` disables expiry.
    """

    def __init__(self, path: str | Path, *, ttl_seconds: float = 0.0) -> None:
        self._path = Path(path)
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS cache ("
            "key TEXT PRIMARY KEY, value TEXT NOT NULL, created_at REAL NOT NULL)"
        )
        self._conn.commit()

    def get(self, key: str) -> Optional[str]:
        with self._lock:
            row = self._conn.execute(
                "SELECT value, created_at FROM cache WHERE key = ?", (key,)
            ).fetchone()
            if row is None:
                return None
            value, created_at = row
            if self._ttl > 0 and time.time() - created_at > self._ttl:
                self._conn.execute("DELETE FROM cache WHERE key = ?", (key,))
                self._conn.commit()
                return None
            return value

    def set(self, key: str, value: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO cache (key, value, created_at) VALUES (?, ?, ?)",
                (key, value, time.time()),
            )
            self._conn.commit()

    def close(self) -> None:  # pragma: no cover - lifecycle helper
        with self._lock:
            self._conn.close()


class LayeredCache:
    """Read-through cache over an ordered list of backends (fast -> durable).

    :meth:`get` consults each backend in order; on a hit it backfills every
    earlier (faster) backend that missed, so a SQLite hit warms the in-memory
    tier. :meth:`set` writes through to every backend.
    """

    def __init__(self, backends: list[CacheBackend]) -> None:
        if not backends:
            raise ValueError("LayeredCache requires at least one backend")
        self._backends = list(backends)

    def get(self, key: str) -> Optional[str]:
        missed: list[CacheBackend] = []
        for backend in self._backends:
            value = backend.get(key)
            if value is not None:
                for earlier in missed:
                    earlier.set(key, value)
                return value
            missed.append(backend)
        return None

    def set(self, key: str, value: str) -> None:
        for backend in self._backends:
            backend.set(key, value)
