from __future__ import annotations

import os
import sys
import threading
import time
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
mcp_client_module.redact_url = lambda value: value
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
    call_log: list[tuple[str, str, dict[str, Any], float | None]] = []
    request_log: list[tuple[str, str, dict[str, Any], float | None]] = []
    blocking_tool_names: set[str] = set()
    tool_started_event = threading.Event()
    tool_release_event = threading.Event()

    def __init__(self, base_url: str, *args: Any, **kwargs: Any):
        self.base_url = base_url

    def list_tools(self, timeout: float | None = None) -> list[_MCPToolSpec]:
        if self.tool_specs_by_url:
            return self.tool_specs_by_url.get(self.base_url, [])
        return self.tool_specs

    def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        timeout: float | None = None,
    ) -> str:
        self.call_log.append((self.base_url, tool_name, dict(arguments), timeout))
        if tool_name in {"stop_active_tool", "stop_active_bash"}:
            self.tool_release_event.set()
            return "stop requested"
        if tool_name in self.blocking_tool_names:
            self.tool_started_event.set()
            self.tool_release_event.wait(timeout=2)
        return f"{tool_name} result"

    def request(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        self.request_log.append((self.base_url, method, dict(params or {}), timeout))
        if method == "tools/stop":
            self.tool_release_event.set()
        return {"result": "ok"}


class PermissionedMCPToolProxyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.original_client = mcp_proxy_tools.MCPClient
        mcp_proxy_tools.MCPClient = _FakeMCPClient
        _FakeMCPClient.tool_specs = []
        _FakeMCPClient.tool_specs_by_url = {}
        _FakeMCPClient.call_log = []
        _FakeMCPClient.request_log = []
        _FakeMCPClient.blocking_tool_names = set()
        _FakeMCPClient.tool_started_event = threading.Event()
        _FakeMCPClient.tool_release_event = threading.Event()

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
        original_api_key = os.environ.pop("TAVILY_API_KEY", None)
        original_tavily_url = os.environ.pop("TAVILY_MCP_URL", None)
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
            _restore_env("TAVILY_API_KEY", original_api_key)
            _restore_env("TAVILY_MCP_URL", original_tavily_url)

    def test_search_mcp_server_specs_from_env_uses_tavily_remote_endpoint(self) -> None:
        original_url = os.environ.pop("SEARCH_MCP_URL", None)
        original_servers = os.environ.pop("SEARCH_MCP_SERVERS", None)
        original_api_key = os.environ.pop("TAVILY_API_KEY", None)
        original_tavily_url = os.environ.pop("TAVILY_MCP_URL", None)
        try:
            os.environ["TAVILY_API_KEY"] = "tvly-test key"

            specs = mcp_proxy_tools.search_mcp_server_specs_from_env()

            self.assertEqual(len(specs), 1)
            self.assertEqual(specs[0].server_id, "search_engine")
            self.assertEqual(
                specs[0].url,
                "https://mcp.tavily.com/mcp/?tavilyApiKey=tvly-test+key",
            )
        finally:
            _restore_env("SEARCH_MCP_URL", original_url)
            _restore_env("SEARCH_MCP_SERVERS", original_servers)
            _restore_env("TAVILY_API_KEY", original_api_key)
            _restore_env("TAVILY_MCP_URL", original_tavily_url)

    def test_phase_two_server_specs_append_tavily_remote_search(self) -> None:
        original_phase2_servers = os.environ.pop("PHASE2_MCP_SERVERS", None)
        original_api_key = os.environ.pop("TAVILY_API_KEY", None)
        original_search_url = os.environ.pop("SEARCH_MCP_URL", None)
        original_search_servers = os.environ.pop("SEARCH_MCP_SERVERS", None)
        original_tavily_url = os.environ.pop("TAVILY_MCP_URL", None)
        try:
            os.environ["PHASE2_MCP_SERVERS"] = "packet=http://packet.example"
            os.environ["TAVILY_API_KEY"] = "tvly-test"

            specs = mcp_proxy_tools.analysis_mcp_server_specs_from_env()

            self.assertEqual(
                [(spec.server_id, spec.url) for spec in specs],
                [
                    ("packet", "http://packet.example"),
                    (
                        "search_engine",
                        "https://mcp.tavily.com/mcp/?tavilyApiKey=tvly-test",
                    ),
                ],
            )
        finally:
            _restore_env("PHASE2_MCP_SERVERS", original_phase2_servers)
            _restore_env("TAVILY_API_KEY", original_api_key)
            _restore_env("SEARCH_MCP_URL", original_search_url)
            _restore_env("SEARCH_MCP_SERVERS", original_search_servers)
            _restore_env("TAVILY_MCP_URL", original_tavily_url)

    def test_phase_two_server_specs_require_phase2_mcp_servers(self) -> None:
        original_phase2_servers = os.environ.pop("PHASE2_MCP_SERVERS", None)
        try:
            with self.assertRaisesRegex(RuntimeError, "PHASE2_MCP_SERVERS must be set"):
                mcp_proxy_tools.analysis_mcp_server_specs_from_env()

            os.environ["PHASE2_MCP_SERVERS"] = "   "
            with self.assertRaisesRegex(RuntimeError, "PHASE2_MCP_SERVERS must be set"):
                mcp_proxy_tools.analysis_mcp_server_specs_from_env()
        finally:
            _restore_env("PHASE2_MCP_SERVERS", original_phase2_servers)

    def test_auto_approved_mcp_tools_expose_search_server_tools(self) -> None:
        _FakeMCPClient.tool_specs_by_url = {
            "http://search.example": [
                _MCPToolSpec("tavily_search", "visible", {"type": "object"}),
                _MCPToolSpec("tavily_extract", "visible", {"type": "object"}),
                _MCPToolSpec("tavily_crawl", "hidden", {"type": "object"}),
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

        self.assertEqual(
            [tool.name for tool in tools],
            ["search_engine__tavily_search", "search_engine__tavily_extract"],
        )
        self.assertIn("Search Engine.tavily_search", catalog)
        self.assertIn("Search Engine.tavily_extract", catalog)
        self.assertNotIn("tavily_crawl", catalog)

    def test_stop_requested_before_worker_start_does_not_call_tool(self) -> None:
        _FakeMCPClient.tool_specs = [
            _MCPToolSpec("long_scan", "visible", {"type": "object"}),
        ]
        finished: list[str] = []
        proxy = mcp_proxy_tools.PermissionedMCPToolProxy(
            [
                mcp_proxy_tools.MCPServerSpec(
                    server_id="hexstrike",
                    label="HexStrike",
                    url="http://hexstrike.example",
                    tool_timeout_seconds=30,
                )
            ],
            approval_callback=lambda _call: (True, ""),
            tool_start_callback=lambda _call: "execution-1",
            tool_stop_requested_callback=lambda _execution_id: True,
            tool_finish_callback=finished.append,
        )
        proxy.build_tools()

        result = proxy.call("hexstrike__long_scan", {"target": "example.com"})

        self.assertEqual(result, "Tool call stopped by user before it started.")
        self.assertEqual(_FakeMCPClient.call_log, [])
        self.assertEqual(finished, ["execution-1"])

    def test_running_tool_stop_requests_server_control_tool(self) -> None:
        _FakeMCPClient.tool_specs = [
            _MCPToolSpec("long_scan", "visible", {"type": "object"}),
            _MCPToolSpec("stop_active_tool", "control", {"type": "object"}),
        ]
        _FakeMCPClient.blocking_tool_names = {"long_scan"}
        finished: list[str] = []
        proxy = mcp_proxy_tools.PermissionedMCPToolProxy(
            [
                mcp_proxy_tools.MCPServerSpec(
                    server_id="hexstrike",
                    label="HexStrike",
                    url="http://hexstrike.example",
                    tool_timeout_seconds=30,
                )
            ],
            approval_callback=lambda _call: (True, ""),
            tool_start_callback=lambda _call: "execution-1",
            tool_stop_requested_callback=(
                lambda _execution_id: _FakeMCPClient.tool_started_event.is_set()
            ),
            tool_finish_callback=finished.append,
        )
        proxy.build_tools()

        result = proxy.call("hexstrike__long_scan", {"target": "example.com"})

        self.assertEqual(result, "Tool call stopped by user.")
        called_tools = [item[1] for item in _FakeMCPClient.call_log]
        self.assertEqual(called_tools, ["long_scan", "stop_active_tool"])
        self.assertEqual(finished, ["execution-1"])

    def test_registered_stop_handler_requests_server_control_tool(self) -> None:
        _FakeMCPClient.tool_specs = [
            _MCPToolSpec("long_scan", "visible", {"type": "object"}),
            _MCPToolSpec("stop_active_tool", "control", {"type": "object"}),
        ]
        _FakeMCPClient.blocking_tool_names = {"long_scan"}
        finished: list[str] = []
        stop_requested = threading.Event()
        registered: dict[str, Any] = {}
        proxy = mcp_proxy_tools.PermissionedMCPToolProxy(
            [
                mcp_proxy_tools.MCPServerSpec(
                    server_id="hexstrike",
                    label="HexStrike",
                    url="http://hexstrike.example",
                    tool_timeout_seconds=30,
                )
            ],
            approval_callback=lambda _call: (True, ""),
            tool_start_callback=lambda _call: "execution-1",
            tool_stop_requested_callback=lambda _execution_id: stop_requested.is_set(),
            tool_stop_handler_callback=(
                lambda execution_id, callback: registered.update(
                    {"execution_id": execution_id, "callback": callback}
                )
            ),
            tool_finish_callback=finished.append,
        )
        proxy.build_tools()
        result: dict[str, str] = {}

        thread = threading.Thread(
            target=lambda: result.update(
                {
                    "value": proxy.call(
                        "hexstrike__long_scan", {"target": "example.com"}
                    )
                }
            )
        )
        thread.start()
        self.assertTrue(_FakeMCPClient.tool_started_event.wait(timeout=2))
        for _ in range(20):
            if "callback" in registered:
                break
            time.sleep(0.05)

        self.assertEqual(registered.get("execution_id"), "execution-1")
        stop_requested.set()
        registered["callback"]()
        thread.join(timeout=5)

        self.assertFalse(thread.is_alive())
        self.assertEqual(result["value"], "Tool call stopped by user.")
        called_tools = [item[1] for item in _FakeMCPClient.call_log]
        self.assertEqual(called_tools, ["long_scan", "stop_active_tool"])
        self.assertEqual(finished, ["execution-1"])

    def test_execution_is_serialized_across_concurrent_calls(self) -> None:
        """Approvals may overlap, but only one approved MCP tool runs at a time."""
        _FakeMCPClient.tool_specs = [
            _MCPToolSpec("scan_a", "visible", {"type": "object"}),
            _MCPToolSpec("scan_b", "visible", {"type": "object"}),
        ]
        proxy = mcp_proxy_tools.PermissionedMCPToolProxy(
            [
                mcp_proxy_tools.MCPServerSpec(
                    server_id="hexstrike",
                    label="HexStrike",
                    url="http://hexstrike.example",
                    tool_timeout_seconds=30,
                )
            ],
            approval_callback=lambda _call: (True, ""),
        )
        proxy.build_tools()

        # Track how many tool executions overlap; the proxy must keep it at 1.
        active = {"current": 0, "max": 0}
        active_lock = threading.Lock()
        original_call_tool = _FakeMCPClient.call_tool

        def tracking_call_tool(self, tool_name, arguments, timeout=None):
            with active_lock:
                active["current"] += 1
                active["max"] = max(active["max"], active["current"])
            time.sleep(0.1)
            with active_lock:
                active["current"] -= 1
            return f"{tool_name} result"

        _FakeMCPClient.call_tool = tracking_call_tool
        results: dict[str, str] = {}
        try:
            def run_call(name: str) -> None:
                results[name] = proxy.call(f"hexstrike__{name}", {})

            threads = [
                threading.Thread(target=run_call, args=(name,))
                for name in ("scan_a", "scan_b")
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)
        finally:
            _FakeMCPClient.call_tool = original_call_tool

        self.assertEqual(active["max"], 1)
        self.assertEqual(
            results, {"scan_a": "scan_a result", "scan_b": "scan_b result"}
        )


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

    def test_custom_analysis_type_is_selectable(self) -> None:
        self.assertIn(
            analysis_types.CUSTOM_ANALYSIS_TYPE,
            analysis_types.ALLOWED_ANALYSIS_TYPES,
        )

    def test_custom_type_uses_the_selected_tool_set(self) -> None:
        tools = analysis_types.hexstrike_mcp_tools_for_analysis_types(
            [analysis_types.CUSTOM_ANALYSIS_TYPE],
            custom_tool_set="Network",
        )

        self.assertEqual(
            tools, frozenset(analysis_types.RECON_PORTS_HEXSTRIKE_MCP_TOOLS)
        )

    def test_custom_type_without_a_tool_set_has_no_hexstrike_tools(self) -> None:
        tools = analysis_types.hexstrike_mcp_tools_for_analysis_types(
            [analysis_types.CUSTOM_ANALYSIS_TYPE]
        )

        self.assertEqual(tools, frozenset())

    def test_description_for_custom_type_is_the_user_goal(self) -> None:
        self.assertEqual(
            analysis_types.description_for_analysis_type(
                analysis_types.CUSTOM_ANALYSIS_TYPE,
                custom_goal="  Probe the upload endpoint  ",
            ),
            "Probe the upload endpoint",
        )

    def test_description_for_fixed_type_ignores_custom_goal(self) -> None:
        self.assertEqual(
            analysis_types.description_for_analysis_type(
                "Configuration", custom_goal="ignored"
            ),
            analysis_types.ANALYSIS_TYPE_DESCRIPTIONS["Configuration"],
        )


if __name__ == "__main__":
    unittest.main()
