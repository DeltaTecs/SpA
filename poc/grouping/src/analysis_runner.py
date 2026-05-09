"""Run simple per-packet purpose analysis for one recording."""

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
    """Analyze every packet in capture order and print its likely purpose."""

    logger.info("Starting packet purpose analysis for recording %d", recording_id)
    packet_ids = _parse_packet_ids(mcp_client.list_packet_ids(recording_id))
    if not packet_ids:
        logger.warning("No packets found for recording %d", recording_id)
        return

    tools = build_langchain_tools(mcp_client, recording_id, packet_ids)
    logger.info("Found %d packets for recording %d", len(packet_ids), recording_id)

    for index, packet_id in enumerate(packet_ids, start=1):
        logger.info(
            "Analyzing packet %d/%d: packet_id=%d",
            index,
            len(packet_ids),
            packet_id,
        )
        try:
            packet_info_text = mcp_client.packet_info(packet_id)
            user_context = format_user_context(
                app_details,
                user_actions,
                _packet_offset_ms(packet_info_text),
            )
            result = analyzer.analyze_packet_purpose(
                packet_id=packet_id,
                packet_info_text=packet_info_text,
                tools=tools,
                recording_id=recording_id,
                user_context=user_context,
                has_app_details=app_details is not None,
                has_user_actions=bool(user_actions),
            )
        except Exception as exc:
            logger.error("Packet %d analysis failed: %s", packet_id, exc)
            result = (
                "Purpose: unknown\n"
                f"Evidence: analysis failed: {exc}\n"
                "Uncertainty: high"
            )

        _print_packet_result(index, len(packet_ids), packet_id, result)

    logger.info("Packet purpose analysis complete")


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


def _print_packet_result(index: int, total: int, packet_id: int, result: str) -> None:
    """Write one stable, grep-friendly packet analysis block to stdout."""

    print(f"\n=== packet {index}/{total} | packet_id:{packet_id} ===", flush=True)
    print(result.strip(), flush=True)
