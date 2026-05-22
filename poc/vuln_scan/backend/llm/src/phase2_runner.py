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
from scan_logger import ScanRunLogger
from user_context import UserAction


logger = logging.getLogger(__name__)


def run_phase_two_analysis(
    *,
    packet_mcp_client: MCPClient,
    analyzer: ScannerAnalyzer,
    event_id: int,
    analysis_types: Sequence[str],
    constraints: str,
    custom_goal: str = "",
    custom_tool_set: str = "",
    bash_mode: bool = False,
    mcp_servers: Sequence[MCPServerSpec],
    approval_callback: ApprovalCallback,
    progress_callback: Callable[[str], None],
    tool_start_callback: ToolStartCallback | None = None,
    tool_stop_requested_callback: ToolStopRequestedCallback | None = None,
    tool_finish_callback: ToolFinishCallback | None = None,
    app_details: Optional[str] = None,
    user_actions: Optional[list[UserAction]] = None,
    prescan_markdown: str = "",
    prior_reports_markdown: str = "",
    reasoning_effort: str = "high",
    max_rounds: Optional[int] = 24,
    scan_logger: Optional[ScanRunLogger] = None,
) -> str:
    logger.info("Starting vulnerability scan phase 2 for event %d", event_id)
    if scan_logger is not None:
        scan_logger.section("PHASE 2 INPUTS")
        scan_logger.log_input("event_id", event_id)
        scan_logger.log_input("analysis_types", list(analysis_types))
        scan_logger.log_input("constraints", constraints)
        scan_logger.log_input("custom_goal", custom_goal or "(none)")
        scan_logger.log_input("custom_tool_set", custom_tool_set or "(none)")
        scan_logger.log_input("bash_mode", bash_mode)
        scan_logger.log_input(
            "mcp_servers",
            [
                {
                    "server_id": server.server_id,
                    "label": server.label,
                    "url": server.url,
                    "tool_timeout_seconds": server.tool_timeout_seconds,
                }
                for server in mcp_servers
            ],
        )
        scan_logger.log_input(
            "app_details",
            app_details if app_details is not None else "(none)",
        )
        scan_logger.log_input(
            "user_actions",
            [
                {
                    "offset_ms": action.offset_ms,
                    "description": action.description,
                }
                for action in (user_actions or [])
            ]
            if user_actions
            else "(none)",
        )
        scan_logger.log_input("prescan_markdown", prescan_markdown or "(none)")
        scan_logger.log_input(
            "prior_reports_markdown", prior_reports_markdown or "(none)"
        )
        scan_logger.log_input(
            "analyzer",
            {
                "provider": analyzer.provider,
                "model": analyzer.model_name,
            },
        )

    def _progress(message: str) -> None:
        if scan_logger is not None:
            scan_logger.log_progress(message)
        progress_callback(message)

    _progress(f"Loading packet context for event {event_id}.")

    prepared = load_prepared_event_context(packet_mcp_client, event_id)
    external_context = prepared.external_context(app_details, user_actions)

    active_mcp_servers = list(mcp_servers)
    if bash_mode:
        # Bash mode: drop the HexStrike MCP server entirely. The LLM runs the
        # underlying CLI tools itself through the Bash MCP server instead.
        active_mcp_servers = [
            server for server in active_mcp_servers if not _is_hexstrike_server(server)
        ]
        allowed_hexstrike_tools = frozenset()
        allowed_tool_names_by_server_id: dict[str, frozenset[str]] = {}
        _progress(
            "Bash mode: HexStrike MCP tools are disabled; the analysis uses the "
            "Bash MCP server (bash, list_cli_tools, cli_tool_usage)."
        )
    else:
        allowed_hexstrike_tools = hexstrike_mcp_tools_for_analysis_types(
            analysis_types, custom_tool_set=custom_tool_set
        )
        hexstrike_server_ids = {
            server.server_id
            for server in active_mcp_servers
            if _is_hexstrike_server(server)
        }
        allowed_tool_names_by_server_id = {
            server_id: allowed_hexstrike_tools for server_id in hexstrike_server_ids
        }
        _progress(
            "Selected analysis tracks enable "
            f"{len(allowed_hexstrike_tools)} HexStrike MCP tools."
        )

    if scan_logger is not None:
        scan_logger.log_input("recording_id", prepared.recording_id)
        scan_logger.log_input("event_context_text", prepared.text)
        scan_logger.log_input("external_context", external_context)
        scan_logger.log_input(
            "allowed_hexstrike_tools", sorted(allowed_hexstrike_tools)
        )

    wrapped_approval = approval_callback
    wrapped_tool_start = tool_start_callback
    wrapped_tool_finish = tool_finish_callback
    wrapped_tool_stop_requested = tool_stop_requested_callback

    if scan_logger is not None:

        def _logging_approval(tool_call: dict) -> tuple[bool, str]:
            scan_logger.log_user_action("tool_approval_requested", tool_call)
            decision = approval_callback(tool_call)
            approved, reason = decision
            scan_logger.log_user_action(
                "tool_approval_decision",
                {
                    "approved": approved,
                    "reason": reason,
                    "exposed_tool_name": tool_call.get("exposed_tool_name"),
                    "tool_name": tool_call.get("tool_name"),
                },
            )
            return decision

        wrapped_approval = _logging_approval

        if tool_start_callback is not None:

            def _logging_tool_start(tool_call: dict) -> str:
                scan_logger.log_tool_request(
                    tool_call.get("exposed_tool_name") or tool_call.get("tool_name") or "tool",
                    tool_call.get("arguments"),
                    source="mcp_proxy",
                )
                execution_id = tool_start_callback(tool_call)
                scan_logger.debug(
                    "TOOL_EXECUTION_STARTED execution_id=%s tool=%s",
                    execution_id,
                    tool_call.get("exposed_tool_name") or tool_call.get("tool_name"),
                )
                return execution_id

            wrapped_tool_start = _logging_tool_start

        if tool_stop_requested_callback is not None:

            def _logging_tool_stop_requested(execution_id: str) -> bool:
                requested = tool_stop_requested_callback(execution_id)
                if requested:
                    scan_logger.log_user_action(
                        "tool_stop_requested",
                        {"execution_id": execution_id},
                    )
                return requested

            wrapped_tool_stop_requested = _logging_tool_stop_requested

        if tool_finish_callback is not None:

            def _logging_tool_finish(execution_id: str) -> None:
                scan_logger.debug(
                    "TOOL_EXECUTION_FINISHED execution_id=%s",
                    execution_id,
                )
                tool_finish_callback(execution_id)

            wrapped_tool_finish = _logging_tool_finish

    proxy = PermissionedMCPToolProxy(
        active_mcp_servers,
        approval_callback=wrapped_approval,
        progress_callback=_progress,
        tool_start_callback=wrapped_tool_start,
        tool_stop_requested_callback=wrapped_tool_stop_requested,
        tool_finish_callback=wrapped_tool_finish,
        allowed_tool_names_by_server_id=allowed_tool_names_by_server_id,
        bash_mode=bash_mode,
    )
    tools = proxy.build_tools()
    tool_catalog = proxy.tool_catalog()

    if scan_logger is not None:
        scan_logger.log_input(
            "phase2_available_tools",
            [getattr(tool, "name", str(tool)) for tool in tools],
        )
        if tool_catalog:
            scan_logger.log_input("phase2_tool_catalog", tool_catalog)

    _progress(
        f"Phase-two analysis has access to {len(tools)} permissioned MCP tools."
    )
    if max_rounds is None:
        _progress("Phase-two LLM tool-call round limit disabled.")
    result = analyzer.analyze_vulnerabilities(
        event_id=event_id,
        recording_id=prepared.recording_id,
        analysis_types=analysis_types,
        constraints=constraints,
        custom_goal=custom_goal,
        event_context=prepared.text,
        tools=tools,
        external_context=external_context,
        prescan_markdown=prescan_markdown,
        prior_reports_markdown=prior_reports_markdown,
        tool_catalog=tool_catalog,
        has_app_details=app_details is not None,
        has_user_actions=bool(user_actions),
        bash_mode=bash_mode,
        max_rounds=max_rounds,
        reasoning_effort=reasoning_effort,
        on_progress=_progress,
        scan_logger=scan_logger,
    )
    _progress("LLM vulnerability analysis finished.")
    if scan_logger is not None:
        scan_logger.section("PHASE 2 OUTPUT")
        scan_logger.log_output("vulnerability_report", result)
    return result


def _is_hexstrike_server(server: MCPServerSpec) -> bool:
    return (
        "hexstrike" in server.server_id.lower()
        or "hexstrike" in server.label.lower()
    )
