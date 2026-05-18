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
) -> ScanSummary:
    logger.info("Starting vulnerability scan phase 1 for event %d", event_id)

    def _progress(message: str) -> None:
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

    _progress("Connecting MCP search tools.")
    search_tools, search_tool_catalog = build_auto_approved_mcp_tools(
        search_mcp_server_specs_from_env()
    )
    tools = [
        *build_langchain_tools(mcp_client, recording_id),
        *search_tools,
    ]
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
    )

    markdown = summary.to_markdown()
    print(markdown)

    if output_path:
        directory = os.path.dirname(output_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as output_file:
            output_file.write(markdown)
            output_file.write("\n")
        logger.info("Wrote phase-one summary to %s", output_path)

    logger.info("Phase 1 complete; phase 2 is was not run")
    return summary
