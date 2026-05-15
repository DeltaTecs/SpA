from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Optional

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field, create_model

from mcp_client import MCPClient, MCPToolSpec


ApprovalCallback = Callable[[dict[str, Any]], bool]
ProgressCallback = Callable[[str], None]
ToolStartCallback = Callable[[dict[str, Any]], str]
ToolStopRequestedCallback = Callable[[str], bool]
ToolFinishCallback = Callable[[str], None]


class ToolCallAborted(RuntimeError):
    pass


CONTROL_TOOL_NAMES = {"stop_active_bash", "stop_active_tool"}


@dataclass(frozen=True)
class MCPServerSpec:
    server_id: str
    label: str
    url: str
    tool_timeout_seconds: float


@dataclass(frozen=True)
class ExposedMCPTool:
    exposed_name: str
    server: MCPServerSpec
    spec: MCPToolSpec


class PermissionedMCPToolProxy:
    """Expose MCP tools to the LLM while blocking each call on UI approval."""

    def __init__(
        self,
        servers: Iterable[MCPServerSpec],
        *,
        approval_callback: ApprovalCallback,
        progress_callback: Optional[ProgressCallback] = None,
        tool_start_callback: Optional[ToolStartCallback] = None,
        tool_stop_requested_callback: Optional[ToolStopRequestedCallback] = None,
        tool_finish_callback: Optional[ToolFinishCallback] = None,
    ):
        self.servers = list(servers)
        self.approval_callback = approval_callback
        self.progress_callback = progress_callback
        self.tool_start_callback = tool_start_callback
        self.tool_stop_requested_callback = tool_stop_requested_callback
        self.tool_finish_callback = tool_finish_callback
        self.clients: dict[str, MCPClient] = {}
        self.exposed_tools: dict[str, ExposedMCPTool] = {}
        self.control_stop_tools: dict[str, str] = {}

    def build_tools(self) -> list[StructuredTool]:
        used_names: set[str] = set()
        tools: list[StructuredTool] = []

        for server in self.servers:
            self._progress(f"Connecting MCP server {server.label} at {server.url}.")
            client = MCPClient(
                server.url,
                connect_timeout=30,
                default_timeout=server.tool_timeout_seconds,
            )
            self.clients[server.server_id] = client
            tool_specs = client.list_tools(timeout=server.tool_timeout_seconds)
            self._progress(f"{server.label}: loaded {len(tool_specs)} MCP tools.")

            for spec in tool_specs:
                if spec.name in CONTROL_TOOL_NAMES:
                    self.control_stop_tools[server.server_id] = spec.name
                    continue

                exposed_name = _exposed_tool_name(server.server_id, spec.name, used_names)
                exposed = ExposedMCPTool(
                    exposed_name=exposed_name,
                    server=server,
                    spec=spec,
                )
                self.exposed_tools[exposed_name] = exposed
                tools.append(self._langchain_tool(exposed))

        return tools

    def tool_catalog(self) -> str:
        lines = ["=== Available Permissioned MCP Tools ==="]
        for exposed in sorted(self.exposed_tools.values(), key=lambda item: item.exposed_name):
            description = exposed.spec.description.strip() or "(no description)"
            lines.append(
                f"- {exposed.exposed_name}: {exposed.server.label}.{exposed.spec.name} - {description}"
            )
        lines.append("=== End Available Permissioned MCP Tools ===")
        return "\n".join(lines)

    def call(self, exposed_name: str, arguments: dict[str, Any]) -> str:
        exposed = self.exposed_tools[exposed_name]
        tool_call = {
            "server_id": exposed.server.server_id,
            "server_label": exposed.server.label,
            "server_url": exposed.server.url,
            "exposed_tool_name": exposed.exposed_name,
            "tool_name": exposed.spec.name,
            "arguments": arguments,
        }
        self._progress(f"Awaiting approval for tool {exposed.exposed_name}.")
        if not self.approval_callback(tool_call):
            return f"Tool call denied by user: {json.dumps(tool_call, sort_keys=True)}"

        self._progress(f"Running approved tool {exposed.exposed_name}.")
        client = self.clients[exposed.server.server_id]
        return self._call_tool_with_user_stop(
            client=client,
            exposed=exposed,
            arguments=arguments,
            tool_call=tool_call,
        )

    def _call_tool_with_user_stop(
        self,
        *,
        client: MCPClient,
        exposed: ExposedMCPTool,
        arguments: dict[str, Any],
        tool_call: dict[str, Any],
    ) -> str:
        if (
            self.tool_start_callback is None
            or self.tool_stop_requested_callback is None
            or self.tool_finish_callback is None
        ):
            return client.call_tool(
                exposed.spec.name,
                arguments,
                timeout=exposed.server.tool_timeout_seconds,
            )

        execution_id = self.tool_start_callback(tool_call)
        done = threading.Event()
        result: dict[str, Any] = {}

        def _worker() -> None:
            try:
                call_client = MCPClient(
                    exposed.server.url,
                    connect_timeout=30,
                    default_timeout=exposed.server.tool_timeout_seconds,
                )
                result["value"] = call_client.call_tool(
                    exposed.spec.name,
                    arguments,
                    timeout=exposed.server.tool_timeout_seconds,
                )
            except BaseException as exc:
                result["error"] = exc
            finally:
                done.set()

        threading.Thread(target=_worker, daemon=True).start()
        try:
            stop_sent = False
            while not done.wait(timeout=0.25):
                if self.tool_stop_requested_callback(execution_id):
                    if not stop_sent:
                        stop_sent = True
                        self._request_server_tool_stop(exposed)
                        done.wait(timeout=2)
                    return "Tool call stopped by user."

            error = result.get("error")
            if isinstance(error, BaseException):
                raise error
            return str(result.get("value", ""))
        finally:
            self.tool_finish_callback(execution_id)

    def _request_server_tool_stop(self, exposed: ExposedMCPTool) -> None:
        stop_tool_name = self.control_stop_tools.get(exposed.server.server_id)
        try:
            stop_client = MCPClient(
                exposed.server.url,
                connect_timeout=5,
                default_timeout=5,
            )
            if stop_tool_name:
                stop_client.call_tool(stop_tool_name, {}, timeout=5)
            else:
                stop_client.request("tools/stop", {}, timeout=5)
        except Exception as exc:
            self._progress(
                f"MCP server stop request failed for {exposed.server.label}: {exc}"
            )

    def _langchain_tool(self, exposed: ExposedMCPTool) -> StructuredTool:
        args_schema = _args_schema(exposed.exposed_name, exposed.spec.input_schema)

        def _invoke(**kwargs: Any) -> str:
            return self.call(exposed.exposed_name, dict(kwargs))

        _invoke.__name__ = exposed.exposed_name
        description = (
            f"{exposed.server.label} MCP tool `{exposed.spec.name}`. "
            f"{exposed.spec.description or 'No description supplied by the MCP server.'}"
        )
        return StructuredTool.from_function(
            func=_invoke,
            name=exposed.exposed_name,
            description=description,
            args_schema=args_schema,
        )

    def _progress(self, message: str) -> None:
        if self.progress_callback:
            self.progress_callback(message)


def analysis_mcp_server_specs_from_env() -> list[MCPServerSpec]:
    timeout = float(os.environ.get("PHASE2_MCP_TOOL_TIMEOUT_SECONDS", "900"))
    raw = os.environ.get("PHASE2_MCP_SERVERS")
    if raw:
        return [
            MCPServerSpec(server_id=server_id, label=label, url=url, tool_timeout_seconds=timeout)
            for server_id, label, url in _parse_server_list(raw)
        ]

    specs = [
        MCPServerSpec(
            server_id="packet",
            label="Packet DB",
            url=os.environ.get("MCP_URL", "http://mcp-packet-db:8765"),
            tool_timeout_seconds=timeout,
        ),
        MCPServerSpec(
            server_id="hexstrike",
            label="HexStrike",
            url=os.environ.get("HEXSTRIKE_MCP_URL", "http://mcp-hexstrike:8767"),
            tool_timeout_seconds=timeout,
        ),
        MCPServerSpec(
            server_id="bash",
            label="Bash",
            url=os.environ.get("BASH_MCP_URL", "http://mcp-hexstrike:8766"),
            tool_timeout_seconds=timeout,
        ),
    ]
    return specs


def _parse_server_list(raw: str) -> list[tuple[str, str, str]]:
    servers: list[tuple[str, str, str]] = []
    for item in raw.split(","):
        item = item.strip()
        if not item or "=" not in item:
            continue
        server_id, url = item.split("=", 1)
        server_id = _safe_identifier(server_id.strip()) or "mcp"
        label = server_id.replace("_", " ").title()
        servers.append((server_id, label, url.strip()))
    return servers


def _args_schema(tool_name: str, input_schema: Dict[str, Any]) -> type[BaseModel]:
    if not isinstance(input_schema, dict) or input_schema.get("type", "object") != "object":
        return create_model(
            f"{_safe_identifier(tool_name).title()}Args",
            value=(Any, Field(default=None, description="Tool argument payload")),
        )

    properties = input_schema.get("properties") or {}
    required = set(input_schema.get("required") or [])
    fields: dict[str, tuple[Any, Any]] = {}
    for raw_name, raw_schema in properties.items():
        field_name = _safe_identifier(str(raw_name))
        if not field_name:
            continue
        schema = raw_schema if isinstance(raw_schema, dict) else {}
        annotation = _annotation_for_schema(schema)
        description = str(schema.get("description") or "")
        if raw_name in required:
            default = Field(..., description=description)
        else:
            default = Field(schema.get("default", None), description=description)
        fields[field_name] = (annotation, default)

    model_name = f"{_safe_identifier(tool_name).title()}Args"
    return create_model(model_name, **fields)


def _annotation_for_schema(schema: Dict[str, Any]) -> Any:
    schema_type = schema.get("type")
    if isinstance(schema_type, list):
        schema_type = next((item for item in schema_type if item != "null"), "string")
    if "enum" in schema:
        return str
    if schema_type == "integer":
        return int
    if schema_type == "number":
        return float
    if schema_type == "boolean":
        return bool
    if schema_type == "array":
        return list[Any]
    if schema_type == "object":
        return dict[str, Any]
    return str


def _exposed_tool_name(server_id: str, tool_name: str, used_names: set[str]) -> str:
    base = f"{_safe_identifier(server_id)}__{_safe_identifier(tool_name)}"
    if len(base) > 64:
        digest = hashlib.sha1(base.encode("utf-8")).hexdigest()[:8]
        base = f"{base[:55]}_{digest}"

    candidate = base
    suffix = 2
    while candidate in used_names:
        suffix_text = f"_{suffix}"
        candidate = f"{base[:64 - len(suffix_text)]}{suffix_text}"
        suffix += 1

    used_names.add(candidate)
    return candidate


def _safe_identifier(value: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_]+", "_", value.strip())
    safe = re.sub(r"_+", "_", safe).strip("_").lower()
    if safe and safe[0].isdigit():
        safe = f"mcp_{safe}"
    return safe
