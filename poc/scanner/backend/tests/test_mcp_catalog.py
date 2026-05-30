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
from llm import McpToolset, ToolSpec  # noqa: E402


def _settings() -> Settings:
    return Settings(
        mcp_packet_db_url="http://packet-db/mcp",
        db_api_url="http://db-api",
        tavily_url="http://tavily/mcp",
        hexstrike_bash_url="http://hexstrike:8766/mcp",
        hexstrike_tools_url="http://hexstrike:8767/mcp",
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


if __name__ == "__main__":
    unittest.main()
