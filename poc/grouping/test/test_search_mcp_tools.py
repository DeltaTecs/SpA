from __future__ import annotations

import sys
import types
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))


class _BaseModel:
    pass


def _field(default: Any = None, *, description: str = "") -> Any:
    return default


def _create_model(name: str, **fields: Any) -> type[_BaseModel]:
    return type(name, (_BaseModel,), {"fields": fields})


class _StructuredTool:
    def __init__(self, *, func: Any, name: str, description: str, args_schema: Any):
        self.func = func
        self.name = name
        self.description = description
        self.args_schema = args_schema

    @classmethod
    def from_function(
        cls,
        *,
        func: Any,
        name: str,
        description: str,
        args_schema: Any,
    ) -> "_StructuredTool":
        return cls(
            func=func,
            name=name,
            description=description,
            args_schema=args_schema,
        )


pydantic_module = types.ModuleType("pydantic")
pydantic_module.BaseModel = _BaseModel
pydantic_module.Field = _field
pydantic_module.create_model = _create_model
try:
    import pydantic  # noqa: F401
except ModuleNotFoundError:
    sys.modules["pydantic"] = pydantic_module

langchain_core_module = types.ModuleType("langchain_core")
langchain_tools_module = types.ModuleType("langchain_core.tools")
langchain_tools_module.StructuredTool = _StructuredTool
try:
    import langchain_core.tools  # noqa: F401
except ModuleNotFoundError:
    sys.modules["langchain_core"] = langchain_core_module
    sys.modules["langchain_core.tools"] = langchain_tools_module


@dataclass(frozen=True)
class _MCPToolSpec:
    name: str
    description: str = ""
    input_schema: dict[str, Any] | None = None


class _PlaceholderMCPClient:
    pass


mcp_client_module = types.ModuleType("mcp_client")
mcp_client_module.MCPClient = _PlaceholderMCPClient
mcp_client_module.MCPToolSpec = _MCPToolSpec
mcp_client_module.redact_url = lambda value: value
sys.modules["mcp_client"] = mcp_client_module

import search_mcp_tools  # noqa: E402


class _FakeMCPClient:
    tool_specs: list[_MCPToolSpec] = []

    def __init__(self, base_url: str):
        self.base_url = base_url

    def list_tools(self, timeout: float | None = None) -> list[_MCPToolSpec]:
        return self.tool_specs

    def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        timeout: float = 30,
    ) -> str:
        return f"{tool_name}:{arguments}"


class SearchMCPToolsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.original_client = search_mcp_tools.MCPClient
        search_mcp_tools.MCPClient = _FakeMCPClient
        _FakeMCPClient.tool_specs = []

    def tearDown(self) -> None:
        search_mcp_tools.MCPClient = self.original_client

    def test_grouping_exposes_only_allowed_tavily_tools(self) -> None:
        _FakeMCPClient.tool_specs = [
            _MCPToolSpec(
                "tavily_search",
                "search",
                {"type": "object", "properties": {"query": {"type": "string"}}},
            ),
            _MCPToolSpec("tavily_extract", "extract", {"type": "object"}),
            _MCPToolSpec("tavily_crawl", "crawl", {"type": "object"}),
        ]
        progress: list[str] = []

        tools, catalog = search_mcp_tools.build_search_mcp_tools(
            [
                search_mcp_tools.MCPServerSpec(
                    server_id="search_engine",
                    label="Search Engine",
                    url="http://search.example",
                    tool_timeout_seconds=30,
                )
            ],
            progress_callback=progress.append,
        )

        self.assertEqual(
            [tool.name for tool in tools],
            ["search_engine__tavily_search", "search_engine__tavily_extract"],
        )
        self.assertIn("Search Engine.tavily_search", catalog)
        self.assertIn("Search Engine.tavily_extract", catalog)
        self.assertNotIn("tavily_crawl", catalog)
        self.assertTrue(
            any("MCP tool hidden from grouping: tavily_crawl" in item for item in progress)
        )


if __name__ == "__main__":
    unittest.main()
