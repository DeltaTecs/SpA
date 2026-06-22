"""Tests for the cost-controlled Tavily toolset assembly and policy.

The Tavily MCP network is stubbed (as in ``llm.tests.test_mcp_toolset``) so no
live server is needed; a fresh in-memory cache is injected for isolation.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config import Settings  # noqa: E402
from app.toolsets import tavily as tavily_mod  # noqa: E402
from app.toolsets.tavily import (  # noqa: E402
    build_tavily_toolset,
    clamp_tavily_args,
    tavily_allowed_tools,
)
from llm.mcp import InMemoryTTLCache  # noqa: E402
from llm.mcp import toolset as toolset_mod  # noqa: E402
from llm.mcp.budget import CallBudget  # noqa: E402

_TAVILY_URL = "https://mcp.tavily.com/mcp/?tavilyApiKey=k"


def _settings(**overrides) -> Settings:
    base = dict(
        mcp_packet_db_url="http://packet-db/mcp",
        tavily_url=_TAVILY_URL,
        hexstrike_bash_url=None,
        hexstrike_tools_url=None,
        hexstrike_tools_admin_token=None,
        openai_api_key=None,
        deepseek_api_key=None,
        db_api_url=None,
        max_concurrency=2,
        default_max_iterations=10,
        mcp_timeout=5.0,
        llm_timeout=5.0,
    )
    base.update(overrides)
    return Settings(**base)


class ClampTavilyArgsTests(unittest.TestCase):
    def test_search_forces_basic_depth_and_caps_results(self):
        out = clamp_tavily_args(
            _settings(tavily_search_depth="basic", tavily_max_results=5),
            "tavily_search",
            {"query": "x", "search_depth": "advanced", "max_results": 20},
        )
        self.assertEqual(out["search_depth"], "basic")
        self.assertEqual(out["max_results"], 5)
        self.assertEqual(out["query"], "x")

    def test_search_keeps_smaller_max_results(self):
        out = clamp_tavily_args(
            _settings(tavily_max_results=5), "tavily_search", {"max_results": 2}
        )
        self.assertEqual(out["max_results"], 2)

    def test_drops_raw_content_unless_enabled(self):
        out = clamp_tavily_args(
            _settings(tavily_include_raw_content=False),
            "tavily_search",
            {"include_raw_content": True},
        )
        self.assertNotIn("include_raw_content", out)

    def test_non_search_tool_untouched_except_raw_content(self):
        out = clamp_tavily_args(
            _settings(), "tavily_extract", {"urls": ["http://a"], "max_results": 50}
        )
        self.assertEqual(out["urls"], ["http://a"])
        self.assertEqual(out["max_results"], 50)  # cap only applies to search


class TavilyAllowedToolsTests(unittest.TestCase):
    def test_defaults_search_and_extract_no_crawl(self):
        allowed = tavily_allowed_tools(_settings())
        self.assertEqual(allowed, {"tavily_search", "tavily_extract"})

    def test_crawl_opt_in(self):
        allowed = tavily_allowed_tools(_settings(tavily_allow_crawl=True))
        self.assertIn("tavily_crawl", allowed)

    def test_extract_opt_out(self):
        allowed = tavily_allowed_tools(_settings(tavily_allow_extract=False))
        self.assertEqual(allowed, {"tavily_search"})


class BuildTavilyToolsetTests(unittest.TestCase):
    def setUp(self):
        self._orig_list = toolset_mod._list_tools_async
        self._orig_call = toolset_mod._call_tool_async
        self.calls = []

        async def fake_list(url, transport):
            return {
                "tools": [
                    {"name": "tavily_search", "inputSchema": {}},
                    {"name": "tavily_extract", "inputSchema": {}},
                    {"name": "tavily_crawl", "inputSchema": {}},
                ]
            }

        async def fake_call(url, transport, name, arguments, timeout):
            self.calls.append((name, arguments))
            return {"content": [{"type": "text", "text": "result"}]}

        toolset_mod._list_tools_async = fake_list
        toolset_mod._call_tool_async = fake_call

    def tearDown(self):
        toolset_mod._list_tools_async = self._orig_list
        toolset_mod._call_tool_async = self._orig_call

    def test_hides_crawl_from_advertised_tools(self):
        ts = build_tavily_toolset(_settings(), cache=InMemoryTTLCache())
        names = {spec.name for spec in ts.list_tool_specs()}
        self.assertEqual(names, {"tavily_search", "tavily_extract"})

    def test_restrict_tools_false_keeps_all_tools_but_still_clamps(self):
        ts = build_tavily_toolset(
            _settings(), cache=InMemoryTTLCache(), restrict_tools=False
        )
        names = {spec.name for spec in ts.list_tool_specs()}
        self.assertEqual(names, {"tavily_search", "tavily_extract", "tavily_crawl"})

        ts.call_tool("tavily_search", {"query": "x", "search_depth": "advanced"})
        self.assertEqual(self.calls[0][1]["search_depth"], "basic")  # clamp still applies

    def test_clamps_args_and_caches_repeat_calls(self):
        ts = build_tavily_toolset(_settings(), cache=InMemoryTTLCache())

        first = ts.call_tool("tavily_search", {"query": "nginx cve", "search_depth": "advanced"})
        second = ts.call_tool("tavily_search", {"query": "nginx cve", "search_depth": "advanced"})

        self.assertEqual(first, "result")
        self.assertEqual(second, "result")
        # Only one real network call; the clamp normalised depth to basic.
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0][1]["search_depth"], "basic")

    def test_budget_blocks_excess_calls(self):
        ts = build_tavily_toolset(
            _settings(), cache=InMemoryTTLCache(), budget=CallBudget(1)
        )
        ts.call_tool("tavily_search", {"query": "a"})
        blocked = ts.call_tool("tavily_search", {"query": "b"})  # distinct -> cache miss

        self.assertIn("budget", blocked.lower())
        self.assertEqual(len(self.calls), 1)


if __name__ == "__main__":
    unittest.main()
