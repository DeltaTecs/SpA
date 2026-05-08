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
):
    """Iterate over all packets in a recording, asking the LLM to classify each."""

    logger.info("Starting analysis for recording %d", recording_id)

    raw = mcp_client.list_packet_ids(recording_id)
    logger.debug("list_packet_ids response:\n%s", raw)

    packet_ids: List[int] = []
    packet_timestamps: dict[int, int] = {}
    for line in raw.splitlines():
        match = re.search(r"packet_id:(\d+)\s+number:\d+\s+timestamp:(\d+)", line)
        if match:
            packet_id = int(match.group(1))
            packet_ids.append(packet_id)
            packet_timestamps[packet_id] = int(match.group(2))

    if not packet_ids:
        logger.warning("No packets found for recording %d", recording_id)
        return

    logger.info("Found %d packets for recording %d", len(packet_ids), recording_id)

    pcap_start_ms = packet_timestamps[packet_ids[0]] if packet_ids else 0
    tools, tracker = build_langchain_tools(mcp_client, recording_id, packet_ids)
    stats = {"total": len(packet_ids), "classified": 0, "errors": 0}

    for index, packet_id in enumerate(packet_ids):
        logger.info(
            "Analyzing packet_id %d  (%d / %d)",
            packet_id,
            index + 1,
            len(packet_ids),
        )

        try:
            packet_info_text = mcp_client.packet_info(packet_id)
        except Exception as e:
            logger.error("  Failed to fetch packet_info for %d: %s", packet_id, e)
            stats["errors"] += 1
            continue

        has_empty_payload = "app payload (first 256 bytes): (empty)" in packet_info_text
        if has_empty_payload and "http header:" not in packet_info_text:
            logger.debug("  Skipping packet_id %d (no payload, not HTTP)", packet_id)
            continue

        packet_offset_ms: Optional[int] = None
        if packet_id in packet_timestamps:
            packet_offset_ms = packet_timestamps[packet_id] - pcap_start_ms

        tracker.reset()
        analyzer.analyze_packet(
            packet_id,
            packet_info_text,
            tools,
            user_context=format_user_context(app_details, user_actions, packet_offset_ms),
            has_app_details=app_details is not None,
            has_user_actions=user_actions is not None,
        )

        if tracker.assigned:
            stats["classified"] += 1
            if tracker.created_description:
                logger.info(
                    "  -> Created and assigned event %d: %s",
                    tracker.event_id,
                    tracker.created_description,
                )
            else:
                logger.info("  -> Assigned to event %d", tracker.event_id)
        else:
            stats["errors"] += 1
            logger.warning("  -> Could not classify packet %d", packet_id)

    logger.info("=" * 60)
    logger.info("Analysis Complete")
    logger.info("  Total packets:  %d", stats["total"])
    logger.info("  Classified:     %d", stats["classified"])
    logger.info("  Errors/skipped: %d", stats["errors"])
    logger.info("=" * 60)
