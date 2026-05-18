from __future__ import annotations

import logging
import os
from typing import Callable, List, Optional

from event_context import load_prepared_event_context
from llm_analyzer import ScannerAnalyzer
from mcp_client import MCPClient
from mcp_proxy_tools import (
    build_auto_approved_mcp_tools,
    search_mcp_server_specs_from_env,
)
from packet_tools import build_langchain_tools
from scan_logger import ScanRunLogger
from scanner_models import ScanSummary
from user_context import UserAction, format_user_context


logger = logging.getLogger(__name__)

def run_phase_one_summary(
    *,
    mcp_client: MCPClient,
    analyzer: ScannerAnalyzer,
    event_id: int,
    app_details: Optional[str] = None,
    user_actions: Optional[List[UserAction]] = None,
    output_path: Optional[str] = None,
    progress_callback: Optional[Callable[[str], None]] = None,
    scan_logger: Optional[ScanRunLogger] = None,
    enable_web_search: bool = False,
) -> ScanSummary:
    logger.info("Starting vulnerability scan phase 1 for event %d", event_id)
    if scan_logger is not None:
        scan_logger.section("PHASE 1 INPUTS")
        scan_logger.log_input("event_id", event_id)
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
        scan_logger.log_input(
            "analyzer",
            {
                "provider": analyzer.provider,
                "model": analyzer.model_name,
            },
        )
        scan_logger.log_input("enable_web_search", enable_web_search)

    def _progress(message: str) -> None:
        if scan_logger is not None:
            scan_logger.log_progress(message)
        if progress_callback is not None:
            progress_callback(message)

    _progress(f"Loading packet context for event {event_id}.")
    prepared = load_prepared_event_context(mcp_client, event_id)
    recording_id = prepared.recording_id
    user_context = format_user_context(
        app_details,
        user_actions,
        prepared.event_start_offset_ms,
        prepared.event_end_offset_ms,
    )

    if scan_logger is not None:
        scan_logger.log_input("recording_id", recording_id)
        scan_logger.log_input("event_context_text", prepared.text)
        scan_logger.log_input("formatted_user_context", user_context)

    if enable_web_search:
        _progress("Connecting MCP search tools.")
        search_tools, search_tool_catalog = build_auto_approved_mcp_tools(
            search_mcp_server_specs_from_env()
        )
    else:
        _progress("Web search disabled for this pre-scan run.")
        search_tools, search_tool_catalog = [], ""
    tools = [
        *build_langchain_tools(mcp_client, recording_id),
        *search_tools,
    ]
    if scan_logger is not None:
        scan_logger.log_input(
            "available_tools",
            [getattr(tool, "name", str(tool)) for tool in tools],
        )
        if search_tool_catalog:
            scan_logger.log_input("search_tool_catalog", search_tool_catalog)
    _progress(f"Pre-scan has access to {len(tools)} MCP tools.")

    _progress("Prompt prepared; invoking LLM pre-scan.")
    summary = analyzer.summarize_event(
        event_id=event_id,
        recording_id=recording_id,
        event_context=prepared.text,
        tools=tools,
        tool_catalog=search_tool_catalog,
        user_context=user_context,
        has_app_details=app_details is not None,
        has_user_actions=bool(user_actions),
        on_progress=progress_callback,
        scan_logger=scan_logger,
    )

    markdown = summary.to_markdown()
    print(markdown)

    if scan_logger is not None:
        scan_logger.section("PHASE 1 OUTPUT")
        scan_logger.log_output("scan_summary_markdown", markdown)
        scan_logger.log_output(
            "scan_summary_fields",
            {
                "event_id": summary.event_id,
                "recording_id": summary.recording_id,
                "most_interesting_packet_id": summary.most_interesting_packet_id,
                "packet_content": summary.packet_content,
                "event_summary": summary.event_summary,
                "suspected_trigger": summary.suspected_trigger,
                "entrypoint_rationale": summary.entrypoint_rationale,
            },
        )

    if output_path:
        directory = os.path.dirname(output_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as output_file:
            output_file.write(markdown)
            output_file.write("\n")
        logger.info("Wrote phase-one summary to %s", output_path)

    logger.info("Phase 1 complete; phase 2 is was not run")
    if scan_logger is not None:
        scan_logger.info("Phase 1 complete.")
    return summary
