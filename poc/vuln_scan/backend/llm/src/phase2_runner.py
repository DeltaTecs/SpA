from __future__ import annotations

import logging
from typing import Callable, Optional, Sequence

from event_context import load_prepared_event_context
from llm_analyzer import ScannerAnalyzer
from mcp_client import MCPClient
from mcp_proxy_tools import (
    ApprovalCallback,
    MCPServerSpec,
    PermissionedMCPToolProxy,
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
    app_details: Optional[str] = None,
    user_actions: Optional[list[UserAction]] = None,
    prescan_markdown: str = "",
) -> str:
    logger.info("Starting vulnerability scan phase 2 for event %d", event_id)
    progress_callback(f"Loading packet context for event {event_id}.")

    prepared = load_prepared_event_context(packet_mcp_client, event_id)
    external_context = prepared.external_context(app_details, user_actions)

    proxy = PermissionedMCPToolProxy(
        mcp_servers,
        approval_callback=approval_callback,
        progress_callback=progress_callback,
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
