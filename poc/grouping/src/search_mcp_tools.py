from __future__ import annotations

import hashlib
import logging
import os
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Optional
from urllib.parse import urlencode

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field, create_model

from mcp_client import MCPClient, MCPToolSpec, redact_url


logger = logging.getLogger(__name__)

ProgressCallback = Callable[[str], None]
# Project-wide cap on Tavily tools exposed to the LLM. Kept in sync with
# TAVILY_ALLOWED_TOOL_NAMES in the vuln_scan mcp_proxy_tools module.
GROUPING_SEARCH_MCP_TOOL_NAMES = frozenset({"tavily_search", "tavily_extract"})
TAVILY_REMOTE_MCP_ENDPOINT = "https://mcp.tavily.com/mcp/"


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


def search_mcp_server_specs_from_env() -> list[MCPServerSpec]:
    """Return optional search-engine MCP servers for packet grouping."""

    timeout = float(os.environ.get("SEARCH_MCP_TOOL_TIMEOUT_SECONDS", "60"))
    raw = os.environ.get("SEARCH_MCP_SERVERS")
    if raw:
        return [
            MCPServerSpec(
                server_id=server_id,
                label=label,
                url=url,
                tool_timeout_seconds=timeout,
            )
            for server_id, label, url in _parse_server_list(raw)
        ]

    url = os.environ.get("SEARCH_MCP_URL") or os.environ.get("TAVILY_MCP_URL")
    if not url:
        tavily_api_key = os.environ.get("TAVILY_API_KEY", "").strip()
        if not tavily_api_key:
            return []
        url = _tavily_remote_mcp_url(tavily_api_key)

    return [
        MCPServerSpec(
            server_id="search_engine",
            label="Search Engine",
            url=url.strip(),
            tool_timeout_seconds=timeout,
        )
    ]


def build_search_mcp_tools_from_env(
    *,
    progress_callback: Optional[ProgressCallback] = None,
    strict: bool = False,
) -> tuple[list[StructuredTool], str]:
    """Build Tavily/search MCP tools if configured; otherwise return no tools."""

    try:
        return build_search_mcp_tools(
            search_mcp_server_specs_from_env(),
            progress_callback=progress_callback,
        )
    except Exception:
        if strict:
            raise
        logger.warning("Search MCP tools unavailable; continuing without them.", exc_info=True)
        return [], ""


def build_search_mcp_tools(
    servers: Iterable[MCPServerSpec],
    *,
    progress_callback: Optional[ProgressCallback] = None,
) -> tuple[list[StructuredTool], str]:
    """Expose only the public search tool allowed in the grouping trust boundary."""

    server_list = list(servers)
    if not server_list:
        return [], ""

    used_names: set[str] = set()
    tools: list[StructuredTool] = []
    catalog_lines = ["=== Available Search MCP Tool ==="]

    for server in server_list:
        _progress(
            progress_callback,
            f"Connecting MCP server {server.label} at {redact_url(server.url)}.",
        )
        client = MCPClient(server.url)
        tool_specs = client.list_tools(timeout=server.tool_timeout_seconds)
        _progress(progress_callback, f"{server.label}: loaded {len(tool_specs)} MCP tools.")

        for spec in tool_specs:
            if spec.name not in GROUPING_SEARCH_MCP_TOOL_NAMES:
                # Tavily also advertises crawl/map/research tools. They are
                # outside the project-wide allowlist and never reach the LLM.
                _progress(
                    progress_callback,
                    f"{server.label}: MCP tool hidden from grouping: {spec.name}",
                )
                continue
            exposed_name = _exposed_tool_name(server.server_id, spec.name, used_names)
            exposed = ExposedMCPTool(
                exposed_name=exposed_name,
                server=server,
                spec=spec,
            )
            tools.append(_langchain_tool(client, exposed))
            description = spec.description.strip() or "(no description)"
            catalog_lines.append(
                f"- {exposed_name}: {server.label}.{spec.name} - {description}"
            )

    if not tools:
        return [], ""

    catalog_lines.append("=== End Available Search MCP Tool ===")
    return tools, "\n".join(catalog_lines)


def _langchain_tool(client: MCPClient, exposed: ExposedMCPTool) -> StructuredTool:
    args_schema = _args_schema(exposed.exposed_name, exposed.spec.input_schema)

    def _invoke(**kwargs: Any) -> str:
        return client.call_tool(
            exposed.spec.name,
            dict(kwargs),
            timeout=exposed.server.tool_timeout_seconds,
        )

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


def _tavily_remote_mcp_url(api_key: str) -> str:
    return f"{TAVILY_REMOTE_MCP_ENDPOINT}?{urlencode({'tavilyApiKey': api_key})}"


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

    return create_model(f"{_safe_identifier(tool_name).title()}Args", **fields)


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


def _progress(callback: Optional[ProgressCallback], message: str) -> None:
    logger.info(message)
    if callback:
        callback(message)
