from __future__ import annotations

import logging
from typing import Callable, Optional, Sequence

from analysis_types import hexstrike_mcp_tools_for_analysis_types
from event_context import load_prepared_event_context
from llm_analyzer import ScannerAnalyzer
from mcp_client import MCPClient
from mcp_proxy_tools import (
    ApprovalCallback,
    MCPServerSpec,
    PermissionedMCPToolProxy,
    ToolFinishCallback,
    ToolStartCallback,
    ToolStopRequestedCallback,
)
from user_context import UserAction


logger = logging.getLogger(__name__)


def run_phase_two_analysis(
    *,
    packet_mcp_client: MCPClient,
    analyzer: ScannerAnalyzer,
    event_id: int,
    analysis_types: Sequence[str],
    constraints: str,
    mcp_servers: Sequence[MCPServerSpec],
    approval_callback: ApprovalCallback,
    progress_callback: Callable[[str], None],
    tool_start_callback: ToolStartCallback | None = None,
    tool_stop_requested_callback: ToolStopRequestedCallback | None = None,
    tool_finish_callback: ToolFinishCallback | None = None,
    app_details: Optional[str] = None,
    user_actions: Optional[list[UserAction]] = None,
    prescan_markdown: str = "",
) -> str:
    logger.info("Starting vulnerability scan phase 2 for event %d", event_id)
    progress_callback(f"Loading packet context for event {event_id}.")

    prepared = load_prepared_event_context(packet_mcp_client, event_id)
    external_context = prepared.external_context(app_details, user_actions)
    allowed_hexstrike_tools = hexstrike_mcp_tools_for_analysis_types(analysis_types)

    hexstrike_server_ids = {
        server.server_id for server in mcp_servers if _is_hexstrike_server(server)
    }
    allowed_tool_names_by_server_id = {
        server_id: allowed_hexstrike_tools for server_id in hexstrike_server_ids
    }
    progress_callback(
        "Selected analysis tracks enable "
        f"{len(allowed_hexstrike_tools)} HexStrike MCP tools."
    )

    proxy = PermissionedMCPToolProxy(
        mcp_servers,
        approval_callback=approval_callback,
        progress_callback=progress_callback,
        tool_start_callback=tool_start_callback,
        tool_stop_requested_callback=tool_stop_requested_callback,
        tool_finish_callback=tool_finish_callback,
        allowed_tool_names_by_server_id=allowed_tool_names_by_server_id,
    )
    tools = proxy.build_tools()
    tool_catalog = proxy.tool_catalog()

    progress_callback(
        f"Phase-two analysis has access to {len(tools)} permissioned MCP tools."
    )
    result = analyzer.analyze_vulnerabilities(
        event_id=event_id,
        recording_id=prepared.recording_id,
        analysis_types=analysis_types,
        constraints=constraints,
        event_context=prepared.text,
        tools=tools,
        external_context=external_context,
        prescan_markdown=prescan_markdown,
        tool_catalog=tool_catalog,
        has_app_details=app_details is not None,
        has_user_actions=bool(user_actions),
        on_progress=progress_callback,
    )
    progress_callback("LLM vulnerability analysis finished.")
    return result


def _is_hexstrike_server(server: MCPServerSpec) -> bool:
    return (
        "hexstrike" in server.server_id.lower()
        or "hexstrike" in server.label.lower()
    )