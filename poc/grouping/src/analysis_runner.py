"""Run packet-to-event assignment for one recording."""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import List, Optional

from llm_analyzer import PacketAnalyzer
from mcp_client import MCPClient
from packet_tools import build_langchain_tools
from user_context import UserAction, format_user_context

try:
    from packet_db_server.database_access import (
        DatabaseAccess,
        database as default_database,
    )
except ModuleNotFoundError as exc:
    if exc.name != "packet_db_server":
        raise

    mcp_src = Path(__file__).resolve().parents[2] / "mcp" / "packet_db_server" / "src"
    if not mcp_src.exists():
        mcp_src = Path("/app/mcp_packet_db_server/src")
    sys.path.insert(0, str(mcp_src))

    from packet_db_server.database_access import (  # type: ignore[no-redef]
        DatabaseAccess,
        database as default_database,
    )


logger = logging.getLogger(__name__)


def run_analysis(
    mcp_client: MCPClient,
    analyzer: PacketAnalyzer,
    recording_id: int,
    app_details: Optional[str] = None,
    user_actions: Optional[List[UserAction]] = None,
    db_access: Optional[DatabaseAccess] = None,
) -> None:
    """Assign payload-bearing packets to events in capture order."""

    logger.info("Starting packet event assignment for recording %d", recording_id)
    db = db_access or default_database
    packet_metadata = db.packet_analysis_metadata_for_recording(recording_id)
    packet_ids = [metadata.packet_id for metadata in packet_metadata]
    if not packet_ids:
        logger.warning("No packets found for recording %d", recording_id)
        return

    logger.info("Found %d packets for recording %d", len(packet_ids), recording_id)
    stats = {"processed": 0, "skipped": 0, "errors": 0}

    for index, metadata in enumerate(packet_metadata, start=1):
        packet_id = metadata.packet_id
        logger.info(
            "Evaluating packet %d/%d: packet_id=%d",
            index,
            len(packet_ids),
            packet_id,
        )
        try:
            if not metadata.has_clear_application_payload:
                stats["skipped"] += 1
                logger.info(
                    "Skipping packet_id=%d because clear application payload is empty",
                    packet_id,
                )
                continue

            packet_info_text = mcp_client.packet_info(packet_id)
            mutation_state = {"done": False}
            tools = build_langchain_tools(
                mcp_client,
                recording_id,
                packet_ids,
                current_packet_id=packet_id,
                mutation_state=mutation_state,
            )
            user_context = format_user_context(
                app_details,
                user_actions,
                metadata.timestamp_offset_ms,
            )
            result = analyzer.assign_packet_to_event(
                packet_id=packet_id,
                packet_info_text=packet_info_text,
                tools=tools,
                recording_id=recording_id,
                user_context=user_context,
                has_app_details=app_details is not None,
                has_user_actions=bool(user_actions),
            )
            if mutation_state.get("done"):
                stats["processed"] += 1
                logger.info(
                    "Packet %d event result: %s",
                    packet_id,
                    _one_line(result),
                )
            else:
                stats["errors"] += 1
                logger.warning(
                    "Packet %d was not assigned by the LLM: %s",
                    packet_id,
                    _one_line(result),
                )
        except Exception as exc:
            stats["errors"] += 1
            logger.error("Packet %d analysis failed: %s", packet_id, exc)

    logger.info(
        "Packet event assignment complete: processed=%d skipped_empty_payload=%d errors=%d",
        stats["processed"],
        stats["skipped"],
        stats["errors"],
    )


def _one_line(text: str) -> str:
    """Compact model result text for logs."""

    return " ".join(text.strip().split())
