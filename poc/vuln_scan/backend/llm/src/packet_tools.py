from __future__ import annotations

try:
    from langchain_core.tools import tool as langchain_tool
except ImportError as exc:
    raise ImportError(
        "langchain packages are required. "
        "Install with: pip install langchain langchain-ollama langchain-community"
    ) from exc

from mcp_client import MCPClient


def build_langchain_tools(mcp: MCPClient, recording_id: int):
    """Expose only the read-only MCP tools"""

    current_recording_id = recording_id

    @langchain_tool
    def packet_info(packet_id: int) -> str:
        """Retrieve rich packet facts for one packet."""
        return mcp.packet_info(packet_id)

    @langchain_tool
    def packet_payload_hexdump(packet_id: int) -> str:
        """Retrieve the full cleartext application payload as hex+ASCII hexdump."""
        return mcp.packet_payload_hexdump(packet_id)

    @langchain_tool
    def conversation_packets(
        conversation_id: int,
        packet_id: int = 0,
        before: int = 5,
        after: int = 5,
    ) -> str:
        """Return rich packet facts for packets in a single conversation."""
        return mcp.conversation_packets(
            conversation_id,
            packet_id=packet_id,
            before=before,
            after=after,
        )

    @langchain_tool
    def packets_in_time_window(
        recording_id: int,
        start_ms: int,
        end_ms: int,
        max_packets: int = 40,
    ) -> str:
        """Return rich packet facts inside a recording-relative time window."""
        if recording_id != current_recording_id:
            return (
                f"recording_id {recording_id} is outside this event summary; "
                f"use recording_id {current_recording_id}"
            )
        return mcp.packets_in_time_window(
            current_recording_id,
            start_ms=start_ms,
            end_ms=end_ms,
            max_packets=max_packets,
        )

    return [
        packet_info,
        packet_payload_hexdump,
        conversation_packets,
        packets_in_time_window,
    ]
