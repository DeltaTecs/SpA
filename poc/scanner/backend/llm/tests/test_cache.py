"""Tests for the tool-call cache backends and key function."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from llm.mcp.cache import (  # noqa: E402
    InMemoryTTLCache,
    LayeredCache,
    SqliteCache,
    make_cache_key,
)


class MakeCacheKeyTests(unittest.TestCase):
    def test_key_is_order_independent(self):
        a = make_cache_key("tavily", "search", {"q": "x", "n": 1})
        b = make_cache_key("tavily", "search", {"n": 1, "q": "x"})
        self.assertEqual(a, b)

    def test_key_sensitive_to_tool_and_args(self):
        base = make_cache_key("tavily", "search", {"q": "x"})
        self.assertNotEqual(base, make_cache_key("tavily", "extract", {"q": "x"}))
        self.assertNotEqual(base, make_cache_key("other", "search", {"q": "x"}))
        self.assertNotEqual(base, make_cache_key("tavily", "search", {"q": "y"}))


class InMemoryTTLCacheTests(unittest.TestCase):
    def test_set_get_roundtrip(self):
        cache = InMemoryTTLCache()
        cache.set("k", "v")
        self.assertEqual(cache.get("k"), "v")
        self.assertIsNone(cache.get("missing"))

    def test_ttl_expiry(self):
        cache = InMemoryTTLCache(ttl_seconds=100)
        cache.set("k", "v")
        # Backdate the entry beyond the TTL without sleeping.
        created_at, value = cache._entries["k"]
        cache._entries["k"] = (created_at - 1000, value)
        self.assertIsNone(cache.get("k"))
        self.assertNotIn("k", cache._entries)  # expired entries are dropped

    def test_lru_eviction(self):
        cache = InMemoryTTLCache(max_entries=2)
        cache.set("a", "1")
        cache.set("b", "2")
        cache.get("a")  # touch 'a' so 'b' is now least-recently-used
        cache.set("c", "3")  # evicts 'b'
        self.assertEqual(cache.get("a"), "1")
        self.assertIsNone(cache.get("b"))
        self.assertEqual(cache.get("c"), "3")


class SqliteCacheTests(unittest.TestCase):
    def setUp(self):
        # ignore_cleanup_errors tolerates SQLite WAL sidecar files on Windows.
        self._dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.path = Path(self._dir.name) / "nested" / "cache.sqlite"
        self._caches = []

    def tearDown(self):
        for cache in self._caches:
            cache.close()  # release the file handle so cleanup can delete it
        self._dir.cleanup()

    def _open(self, **kwargs) -> SqliteCache:
        cache = SqliteCache(self.path, **kwargs)
        self._caches.append(cache)
        return cache

    def test_roundtrip_and_creates_parent_dir(self):
        cache = self._open()
        self.assertTrue(self.path.parent.exists())
        cache.set("k", "v")
        self.assertEqual(cache.get("k"), "v")
        self.assertIsNone(cache.get("missing"))

    def test_persists_across_instances(self):
        self._open().set("k", "v")
        self.assertEqual(self._open().get("k"), "v")

    def test_ttl_expiry(self):
        cache = self._open(ttl_seconds=100)
        cache.set("k", "v")
        cache._conn.execute("UPDATE cache SET created_at = created_at - 1000")
        cache._conn.commit()
        self.assertIsNone(cache.get("k"))


class LayeredCacheTests(unittest.TestCase):
    def test_requires_a_backend(self):
        with self.assertRaises(ValueError):
            LayeredCache([])

    def test_read_through_backfills_faster_tier(self):
        fast = InMemoryTTLCache()
        slow = InMemoryTTLCache()
        slow.set("k", "v")  # only the durable tier has it
        layered = LayeredCache([fast, slow])

        self.assertEqual(layered.get("k"), "v")
        self.assertEqual(fast.get("k"), "v")  # promoted into the fast tier

    def test_set_writes_through_to_all(self):
        fast = InMemoryTTLCache()
        slow = InMemoryTTLCache()
        LayeredCache([fast, slow]).set("k", "v")
        self.assertEqual(fast.get("k"), "v")
        self.assertEqual(slow.get("k"), "v")


if __name__ == "__main__":
    unittest.main()
