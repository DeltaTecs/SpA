"""Tests for the cost-control toolset wrappers (no network/MCP)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from llm.mcp.budget import CallBudget  # noqa: E402
from llm.mcp.cache import InMemoryTTLCache  # noqa: E402
from llm.mcp.wrappers import (  # noqa: E402
    BudgetToolset,
    CachingToolset,
    PolicyToolset,
)
from llm.provider.base import ToolSpec  # noqa: E402


def _spec(name):
    return ToolSpec(name=name, description=f"desc {name}", parameters={"type": "object"})


class FakeToolset:
    """Records every call and returns a fixed (or per-name) output."""

    def __init__(self, specs, *, name="fake", output="out"):
        self.name = name
        self._specs = specs
        self._output = output
        self.calls = []

    def list_tool_specs(self):
        return self._specs

    def call_tool(self, name, arguments):
        self.calls.append((name, dict(arguments)))
        return self._output


class CachingToolsetTests(unittest.TestCase):
    def test_identical_calls_hit_inner_once(self):
        inner = FakeToolset([_spec("search")])
        cached = CachingToolset(inner, InMemoryTTLCache(), key_namespace="ns")

        first = cached.call_tool("search", {"q": "x"})
        second = cached.call_tool("search", {"q": "x"})

        self.assertEqual(first, "out")
        self.assertEqual(second, "out")
        self.assertEqual(len(inner.calls), 1)  # second served from cache

    def test_different_args_miss(self):
        inner = FakeToolset([_spec("search")])
        cached = CachingToolset(inner, InMemoryTTLCache(), key_namespace="ns")

        cached.call_tool("search", {"q": "x"})
        cached.call_tool("search", {"q": "y"})
        self.assertEqual(len(inner.calls), 2)

    def test_namespace_isolates_keys(self):
        inner = FakeToolset([_spec("search")])
        cache = InMemoryTTLCache()
        CachingToolset(inner, cache, key_namespace="a").call_tool("search", {"q": "x"})
        CachingToolset(inner, cache, key_namespace="b").call_tool("search", {"q": "x"})
        self.assertEqual(len(inner.calls), 2)  # different namespaces -> distinct keys

    def test_list_tool_specs_delegated(self):
        inner = FakeToolset([_spec("search")])
        cached = CachingToolset(inner, InMemoryTTLCache())
        self.assertEqual([s.name for s in cached.list_tool_specs()], ["search"])


class BudgetToolsetTests(unittest.TestCase):
    def test_passes_through_under_limit(self):
        inner = FakeToolset([_spec("search")])
        budgeted = BudgetToolset(inner, CallBudget(2))
        self.assertEqual(budgeted.call_tool("search", {}), "out")
        self.assertEqual(budgeted.call_tool("search", {}), "out")
        self.assertEqual(len(inner.calls), 2)

    def test_short_circuits_when_exhausted(self):
        inner = FakeToolset([_spec("search")])
        budgeted = BudgetToolset(inner, CallBudget(1))
        budgeted.call_tool("search", {})
        blocked = budgeted.call_tool("search", {})
        self.assertEqual(blocked, BudgetToolset.EXHAUSTED_NOTE)
        self.assertEqual(len(inner.calls), 1)  # the blocked call never reached inner

    def test_none_budget_is_passthrough(self):
        inner = FakeToolset([_spec("search")])
        budgeted = BudgetToolset(inner, None)
        for _ in range(5):
            budgeted.call_tool("search", {})
        self.assertEqual(len(inner.calls), 5)


class PolicyToolsetTests(unittest.TestCase):
    def test_filters_advertised_specs(self):
        inner = FakeToolset([_spec("search"), _spec("crawl")])
        policy = PolicyToolset(inner, allowed_tool_names={"search"})
        self.assertEqual([s.name for s in policy.list_tool_specs()], ["search"])

    def test_blocks_disallowed_call(self):
        inner = FakeToolset([_spec("search"), _spec("crawl")])
        policy = PolicyToolset(inner, allowed_tool_names={"search"})
        out = policy.call_tool("crawl", {})
        self.assertIn("not available", out)
        self.assertEqual(inner.calls, [])

    def test_transforms_arguments_before_dispatch(self):
        inner = FakeToolset([_spec("search")])
        policy = PolicyToolset(
            inner,
            transform_args=lambda name, args: {**args, "search_depth": "basic"},
        )
        policy.call_tool("search", {"q": "x"})
        self.assertEqual(inner.calls, [("search", {"q": "x", "search_depth": "basic"})])


if __name__ == "__main__":
    unittest.main()
