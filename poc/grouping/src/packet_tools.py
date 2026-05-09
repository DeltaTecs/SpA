from __future__ import annotations

import re
from typing import List

try:
    from langchain_core.tools import tool as langchain_tool
except ImportError as e:
    raise ImportError(
        "langchain packages are required. "
        "Install with: pip install langchain langchain-ollama langchain-community"
    ) from e

from mcp_client import MCPClient


def build_langchain_tools(mcp: MCPClient, recording_id: int, packet_ids: List[int]):
    """Build read-only LangChain tools for packet context lookups."""

    # Capture the recording ID so tool calls cannot inspect arbitrary recordings
    # through the time-window helper.
    current_recording_id = recording_id

    @langchain_tool
    def get_packet_info(packet_id: int) -> str:
        """Retrieve rich packet facts and a payload preview for any packet."""
        return mcp.packet_info(packet_id)

    @langchain_tool
    def get_full_payload(packet_id: int) -> str:
        """Retrieve the full cleartext application payload as a hexdump."""
        return mcp.call_tool("packet_payload_hexdump", {"packet_id": packet_id})

    @langchain_tool
    def get_surrounding_packets(packet_id: int, window: int = 2) -> str:
        """Return nearby packets, preferring the current packet's conversation."""
        window = max(0, min(window, 50))
        pkt_info = mcp.packet_info(packet_id)
        match = re.search(r"^conversation_id:\s*(\d+)\s*$", pkt_info, re.MULTILINE)
        if match:
            return mcp.conversation_packets(
                int(match.group(1)),
                packet_id=packet_id,
                before=window,
                after=window,
            )

        try:
            idx = packet_ids.index(packet_id)
        except ValueError:
            return f"packet_id {packet_id} not in current recording"

        # Packets without a conversation still get a bounded global fallback.
        start = max(0, idx - window)
        end = min(len(packet_ids), idx + window + 1)
        parts: list[str] = []
        for pid in packet_ids[start:end]:
            marker = "  <-- current" if pid == packet_id else ""
            header = f"=== packet_id:{pid}{marker} ==="
            parts.append(f"{header}\n{mcp.packet_info(pid)}")
        return (
            "Fallback: packet has no conversation_id; using global packet order.\n\n"
            + "\n\n".join(parts)
        )

    @langchain_tool
    def get_conversation_packets(
        conversation_id: int,
        packet_id: int = 0,
        before: int = 5,
        after: int = 5,
    ) -> str:
        """Return packets from one conversation around packet_id."""
        return mcp.conversation_packets(
            conversation_id,
            packet_id=packet_id,
            before=before,
            after=after,
        )

    @langchain_tool
    def get_packets_in_time_window(
        recording_id: int,
        start_ms: int,
        end_ms: int,
        max_packets: int = 40,
    ) -> str:
        """Return packets inside a recording-relative time window."""
        if recording_id != current_recording_id:
            return (
                f"recording_id {recording_id} is outside this analysis; "
                f"use recording_id {current_recording_id}"
            )
        return mcp.packets_in_time_window(
            current_recording_id,
            start_ms=start_ms,
            end_ms=end_ms,
            max_packets=max_packets,
        )

    tools = [
        get_packet_info,
        get_full_payload,
        get_surrounding_packets,
        get_conversation_packets,
        get_packets_in_time_window,
    ]
    return tools
