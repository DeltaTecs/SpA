"""Run packet-to-event assignment for one recording."""

from __future__ import annotations

import logging
import re
from typing import List, Optional

from llm_analyzer import PacketAnalyzer
from mcp_client import MCPClient
from packet_tools import build_langchain_tools
from user_context import UserAction, format_user_context


logger = logging.getLogger(__name__)


def run_analysis(
    mcp_client: MCPClient,
    analyzer: PacketAnalyzer,
    recording_id: int,
    app_details: Optional[str] = None,
    user_actions: Optional[List[UserAction]] = None,
) -> None:
    """Assign payload-bearing packets to events in capture order."""

    logger.info("Starting packet event assignment for recording %d", recording_id)
    packet_ids = _parse_packet_ids(mcp_client.list_packet_ids(recording_id))
    if not packet_ids:
        logger.warning("No packets found for recording %d", recording_id)
        return

    logger.info("Found %d packets for recording %d", len(packet_ids), recording_id)
    stats = {"processed": 0, "skipped": 0, "errors": 0}

    for index, packet_id in enumerate(packet_ids, start=1):
        logger.info(
            "Evaluating packet %d/%d: packet_id=%d",
            index,
            len(packet_ids),
            packet_id,
        )
        try:
            packet_info_text = mcp_client.packet_info(packet_id)
            if not _has_clear_application_payload(packet_info_text):
                stats["skipped"] += 1
                logger.info(
                    "Skipping packet_id=%d because clear application payload is empty",
                    packet_id,
                )
                continue

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
                _packet_offset_ms(packet_info_text),
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


def _parse_packet_ids(raw: str) -> List[int]:
    """Extract packet IDs from the MCP list_packet_ids text response."""

    packet_ids: List[int] = []
    seen: set[int] = set()
    for match in re.finditer(r"\bpacket_id:(\d+)\b", raw):
        packet_id = int(match.group(1))
        if packet_id not in seen:
            packet_ids.append(packet_id)
            seen.add(packet_id)
    return packet_ids


def _packet_offset_ms(packet_info_text: str) -> Optional[int]:
    """Read the recording-relative timestamp from packet_info when present."""

    match = re.search(
        r"^timestamp offset:\s*(-?\d+)\s+ms",
        packet_info_text,
        flags=re.MULTILINE,
    )
    return int(match.group(1)) if match else None


def _has_clear_application_payload(packet_info_text: str) -> bool:
    """Return true when packet_info reports non-empty clear app payload."""

    match = re.search(
        r"^payload length:\s*(\d+)\s+bytes",
        packet_info_text,
        flags=re.MULTILINE,
    )
    return bool(match and int(match.group(1)) > 0)


def _one_line(text: str) -> str:
    """Compact model result text for logs."""

    return re.sub(r"\s+", " ", text.strip())
