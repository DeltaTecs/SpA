from __future__ import annotations

import os
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


@dataclass(frozen=True)
class _MCPToolSpec:
    name: str
    description: str = ""
    input_schema: dict[str, Any] | None = None


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

mcp_client_module = types.ModuleType("mcp_client")
mcp_client_module.MCPToolSpec = _MCPToolSpec
mcp_client_module.MCPClient = object
try:
    import mcp_client  # noqa: F401
except ModuleNotFoundError:
    sys.modules["mcp_client"] = mcp_client_module

import analysis_types  # noqa: E402
import mcp_proxy_tools  # noqa: E402


def _restore_env(name: str, value: str | None) -> None:
    if value is None:
        os.environ.pop(name, None)
    else:
        os.environ[name] = value


class _FakeMCPClient:
    tool_specs: list[_MCPToolSpec] = []
    tool_specs_by_url: dict[str, list[_MCPToolSpec]] = {}

    def __init__(self, base_url: str, *args: Any, **kwargs: Any):
        self.base_url = base_url

    def list_tools(self, timeout: float | None = None) -> list[_MCPToolSpec]:
        if self.tool_specs_by_url:
            return self.tool_specs_by_url.get(self.base_url, [])
        return self.tool_specs


class PermissionedMCPToolProxyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.original_client = mcp_proxy_tools.MCPClient
        mcp_proxy_tools.MCPClient = _FakeMCPClient
        _FakeMCPClient.tool_specs = []
        _FakeMCPClient.tool_specs_by_url = {}

    def tearDown(self) -> None:
        mcp_proxy_tools.MCPClient = self.original_client

    def test_phase_two_hides_selected_packet_db_tools(self) -> None:
        _FakeMCPClient.tool_specs = [
            _MCPToolSpec("packet_info", "hidden", {"type": "object", "properties": {}}),
            _MCPToolSpec("packet_payload_hexdump", "hidden", {"type": "object"}),
            _MCPToolSpec("packets_in_time_window", "hidden", {"type": "object"}),
            _MCPToolSpec("event_packets", "hidden", {"type": "object"}),
            _MCPToolSpec("conversation_packets", "visible", {"type": "object"}),
            _MCPToolSpec("stop_active_tool", "control", {"type": "object"}),
        ]
        progress: list[str] = []
        proxy = mcp_proxy_tools.PermissionedMCPToolProxy(
            [
                mcp_proxy_tools.MCPServerSpec(
                    server_id="packet",
                    label="Packet DB",
                    url="http://packet-db.example",
                    tool_timeout_seconds=30,
                )
            ],
            approval_callback=lambda _call: True,
            progress_callback=progress.append,
        )

        tools = proxy.build_tools()

        self.assertEqual([tool.name for tool in tools], ["packet__conversation_packets"])
        self.assertEqual(set(proxy.exposed_tools), {"packet__conversation_packets"})
        self.assertEqual(proxy.control_stop_tools, {"packet": "stop_active_tool"})
        self.assertNotIn("packet_info", proxy.tool_catalog())
        self.assertTrue(
            any("MCP tool hidden from phase two: packet_info" in item for item in progress)
        )

    def test_hexstrike_allowlist_does_not_filter_packet_db_or_bash_tools(self) -> None:
        _FakeMCPClient.tool_specs_by_url = {
            "http://packet-db.example": [
                _MCPToolSpec("packet_info", "hidden", {"type": "object"}),
                _MCPToolSpec("conversation_packets", "visible", {"type": "object"}),
            ],
            "http://hexstrike.example": [
                _MCPToolSpec("nmap_scan", "visible", {"type": "object"}),
                _MCPToolSpec("sqlmap_scan", "not for track", {"type": "object"}),
                _MCPToolSpec("httpx_probe", "visible", {"type": "object"}),
                _MCPToolSpec("stop_active_tool", "control", {"type": "object"}),
            ],
            "http://bash.example": [
                _MCPToolSpec("bash", "visible", {"type": "object"}),
            ],
            "http://search.example": [
                _MCPToolSpec("tavily_search", "visible", {"type": "object"}),
            ],
        }
        proxy = mcp_proxy_tools.PermissionedMCPToolProxy(
            [
                mcp_proxy_tools.MCPServerSpec(
                    server_id="packet",
                    label="Packet DB",
                    url="http://packet-db.example",
                    tool_timeout_seconds=30,
                ),
                mcp_proxy_tools.MCPServerSpec(
                    server_id="hexstrike",
                    label="HexStrike",
                    url="http://hexstrike.example",
                    tool_timeout_seconds=30,
                ),
                mcp_proxy_tools.MCPServerSpec(
                    server_id="bash",
                    label="Bash",
                    url="http://bash.example",
                    tool_timeout_seconds=30,
                ),
                mcp_proxy_tools.MCPServerSpec(
                    server_id="search_engine",
                    label="Search Engine",
                    url="http://search.example",
                    tool_timeout_seconds=30,
                ),
            ],
            approval_callback=lambda _call: True,
            allowed_tool_names_by_server_id={
                "hexstrike": {"nmap_scan", "httpx_probe"},
            },
        )

        tools = proxy.build_tools()

        self.assertEqual(
            [tool.name for tool in tools],
            [
                "packet__conversation_packets",
                "hexstrike__nmap_scan",
                "hexstrike__httpx_probe",
                "bash__bash",
                "search_engine__tavily_search",
            ],
        )
        self.assertEqual(proxy.control_stop_tools, {"hexstrike": "stop_active_tool"})
        self.assertNotIn("sqlmap_scan", proxy.tool_catalog())

    def test_search_mcp_server_specs_from_env_uses_search_url(self) -> None:
        original_url = os.environ.pop("SEARCH_MCP_URL", None)
        original_servers = os.environ.pop("SEARCH_MCP_SERVERS", None)
        original_timeout = os.environ.pop("SEARCH_MCP_TOOL_TIMEOUT_SECONDS", None)
        try:
            self.assertEqual(mcp_proxy_tools.search_mcp_server_specs_from_env(), [])

            os.environ["SEARCH_MCP_URL"] = "http://search.example"
            os.environ["SEARCH_MCP_TOOL_TIMEOUT_SECONDS"] = "12"

            specs = mcp_proxy_tools.search_mcp_server_specs_from_env()

            self.assertEqual(len(specs), 1)
            self.assertEqual(specs[0].server_id, "search_engine")
            self.assertEqual(specs[0].label, "Search Engine")
            self.assertEqual(specs[0].url, "http://search.example")
            self.assertEqual(specs[0].tool_timeout_seconds, 12)
        finally:
            _restore_env("SEARCH_MCP_URL", original_url)
            _restore_env("SEARCH_MCP_SERVERS", original_servers)
            _restore_env("SEARCH_MCP_TOOL_TIMEOUT_SECONDS", original_timeout)

    def test_auto_approved_mcp_tools_expose_search_server_tools(self) -> None:
        _FakeMCPClient.tool_specs_by_url = {
            "http://search.example": [
                _MCPToolSpec("tavily_search", "visible", {"type": "object"}),
            ],
        }

        tools, catalog = mcp_proxy_tools.build_auto_approved_mcp_tools(
            [
                mcp_proxy_tools.MCPServerSpec(
                    server_id="search_engine",
                    label="Search Engine",
                    url="http://search.example",
                    tool_timeout_seconds=30,
                )
            ]
        )

        self.assertEqual([tool.name for tool in tools], ["search_engine__tavily_search"])
        self.assertIn("Search Engine.tavily_search", catalog)


class AnalysisTypesTest(unittest.TestCase):
    def test_hexstrike_tools_for_analysis_types_returns_selected_union(self) -> None:
        tools = analysis_types.hexstrike_mcp_tools_for_analysis_types(
            ["Recon: Domain", "Recon: Ports"]
        )

        self.assertIn("amass_scan", tools)
        self.assertIn("autorecon_scan", tools)
        self.assertIn("nmap_scan", tools)
        self.assertNotIn("sqlmap_scan", tools)

    def test_configuration_analysis_type_exposes_configuration_tools(self) -> None:
        tools = analysis_types.hexstrike_mcp_tools_for_analysis_types(["Configuration"])

        self.assertIn("nuclei_scan", tools)
        self.assertIn("checkov_iac_scan", tools)
        self.assertIn("prowler_scan", tools)
        self.assertIn("format_tool_output_visual", tools)

    def test_post_recon_analysis_types_expose_post_recon_tools(self) -> None:
        labels = ("Post Recon - Explorative", "Post Recon - High Impact")

        for label in labels:
            with self.subTest(label=label):
                tools = analysis_types.hexstrike_mcp_tools_for_analysis_types([label])

                self.assertIn(label, analysis_types.ALLOWED_ANALYSIS_TYPES)
                self.assertIn("gobuster_scan", tools)
                self.assertIn("create_file", tools)
                self.assertIn("execute_python_script", tools)
                self.assertIn("metasploit_run", tools)
                self.assertIn("bugbounty_file_upload_testing", tools)
                self.assertIn("burpsuite_alternative_scan", tools)
                self.assertEqual(
                    tools, frozenset(analysis_types.POST_RECON_HEXSTRIKE_MCP_TOOLS)
                )

    def test_unknown_analysis_type_has_no_hexstrike_tools(self) -> None:
        tools = analysis_types.hexstrike_mcp_tools_for_analysis_types(["Unknown"])

        self.assertEqual(tools, frozenset())


if __name__ == "__main__":
    unittest.main()
