"""Tests for the pentest MCP catalogue selection policy (no network)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config import Settings  # noqa: E402
from app.mcp_catalog import (  # noqa: E402
    build_catalog,
    enumerate_catalog,
    list_selectable_tool_specs,
)
from app.toolsets import tavily as tavily_mod  # noqa: E402
from llm import CallBudget, McpToolset, ToolSpec  # noqa: E402
from llm.mcp import toolset as toolset_mod  # noqa: E402


def _settings() -> Settings:
    return Settings(
        mcp_packet_db_url="http://packet-db/mcp",
        db_api_url="http://db-api",
        tavily_url="http://tavily/mcp",
        hexstrike_bash_url="http://hexstrike:8766/mcp",
        hexstrike_tools_url="http://hexstrike:8767/mcp",
        hexstrike_tools_admin_token="test-admin-token",
        openai_api_key=None,
        deepseek_api_key=None,
        max_concurrency=4,
        default_max_iterations=10,
        mcp_timeout=60.0,
        llm_timeout=120.0,
    )


def _spec(name: str) -> ToolSpec:
    return ToolSpec(name=name, description=f"description for {name}", parameters={})


class SelectableCatalogTests(unittest.TestCase):
    def setUp(self):
        specs_by_toolset = {
            "packet-db": [_spec("packet_lookup")],
            "tavily": [_spec("tavily_search"), _spec("tavily_crawl")],
            "hexstrike-bash": [_spec("bash"), _spec("stop_active_bash")],
            "hexstrike-tools": [_spec("nmap_scan"), _spec("not_for_pentest")],
        }

        def fake_list_tool_specs(toolset):
            return specs_by_toolset[toolset.name]

        self._original_list_tool_specs = McpToolset.list_tool_specs
        McpToolset.list_tool_specs = fake_list_tool_specs

    def tearDown(self):
        McpToolset.list_tool_specs = self._original_list_tool_specs

    def test_hexstrike_tools_are_limited_to_the_pentest_allowlist(self):
        entries = {entry.name: entry for entry in build_catalog(_settings())}

        tools = list_selectable_tool_specs(entries["hexstrike-tools"])

        self.assertEqual([tool.name for tool in tools], ["nmap_scan"])

    def test_other_categories_are_not_filtered_by_the_hexstrike_allowlist(self):
        entries = {entry.name: entry for entry in build_catalog(_settings())}

        tools = list_selectable_tool_specs(entries["hexstrike-bash"])

        self.assertEqual([tool.name for tool in tools], ["bash", "stop_active_bash"])

    def test_enumeration_discards_requested_non_selectable_tools(self):
        tools = enumerate_catalog(
            _settings(),
            allowed={"packet_lookup", "tavily_search", "bash", "nmap_scan", "not_for_pentest"},
            include_exempt=True,
        )

        self.assertEqual(
            tools.allowed_names,
            {"packet_lookup", "tavily_search", "bash", "nmap_scan"},
        )
        self.assertEqual(tools.needed_categories, {"db", "search", "bash", "hexstrike"})
        self.assertEqual(tools.exempt_names, {"packet_lookup", "tavily_search", "tavily_crawl"})


class CatalogTavilyCostControlTests(unittest.TestCase):
    """The catalogue's Tavily entry is the cost-controlled wrapper, not a raw toolset.

    The MCP network is stubbed at the module level and the process-wide Tavily
    cache is reset per test for isolation.
    """

    def setUp(self):
        tavily_mod._cache = None  # fresh in-memory cache singleton
        self._orig_list = toolset_mod._list_tools_async
        self._orig_call = toolset_mod._call_tool_async
        self.calls = []

        async def fake_list(url, transport):
            return {
                "tools": [
                    {"name": "tavily_search", "inputSchema": {}},
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
        tavily_mod._cache = None

    def _tavily_toolset(self, **kwargs):
        entries = {entry.name: entry for entry in build_catalog(_settings(), **kwargs)}
        return entries["tavily"].toolset

    def test_search_entry_advertises_all_tools(self):
        # restrict_tools=False -> operator selection governs; crawl stays visible.
        names = {spec.name for spec in self._tavily_toolset().list_tool_specs()}
        self.assertEqual(names, {"tavily_search", "tavily_crawl"})

    def test_search_entry_caches_and_clamps(self):
        ts = self._tavily_toolset()
        ts.call_tool("tavily_search", {"query": "nginx", "search_depth": "advanced"})
        ts.call_tool("tavily_search", {"query": "nginx", "search_depth": "advanced"})

        self.assertEqual(len(self.calls), 1)  # repeat served from the shared cache
        self.assertEqual(self.calls[0][1]["search_depth"], "basic")  # clamped to basic

    def test_budget_shared_across_catalog_rebuilds(self):
        budget = CallBudget(1)
        # Each item session rebuilds the catalogue but shares the job's budget.
        self._tavily_toolset(budget=budget).call_tool("tavily_search", {"query": "a"})
        blocked = self._tavily_toolset(budget=budget).call_tool(
            "tavily_search", {"query": "b"}
        )

        self.assertIn("budget", blocked.lower())
        self.assertEqual(len(self.calls), 1)


if __name__ == "__main__":
    unittest.main()
