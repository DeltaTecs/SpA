from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

try:
    from langchain_core.tools import tool as langchain_tool
except ImportError as e:
    raise ImportError(
        "langchain packages are required. "
        "Install with: pip install langchain langchain-ollama langchain-community"
    ) from e

from mcp_client import MCPClient


def build_langchain_tools(
    mcp: MCPClient,
    recording_id: int,
    packet_ids: List[int],
    current_packet_id: Optional[int] = None,
    mutation_state: Optional[Dict[str, Any]] = None,
):
    """Build LangChain tools for current-packet event assignment."""

    # Capture the recording ID so tool calls cannot inspect arbitrary recordings
    # through the time-window helper.
    current_recording_id = recording_id
    if mutation_state is None:
        mutation_state = {}
    mutation_state.setdefault("done", False)

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

    @langchain_tool
    def get_matching_events() -> str:
        """Return existing events whose assigned packets match this packet's tuple."""
        if current_packet_id is None:
            return "No current packet is bound to this tool set."
        return mcp.events_for_recording(current_recording_id, packet_id=current_packet_id)

    @langchain_tool
    def assign_current_packet_to_event(
        event_id: int,
        reason: str,
        confidence: float,
    ) -> str:
        """Assign the current packet with rationale and confidence."""
        if current_packet_id is None:
            return "No current packet is bound to this tool set."
        if mutation_state["done"]:
            return "A mutating event tool was already called for this packet."
        result = mcp.assign_packet_to_event(
            current_packet_id,
            event_id,
            reason=reason,
            confidence=confidence,
        )
        if result.strip().lower() == "ok":
            mutation_state["done"] = True
            mutation_state["action"] = "assigned"
            mutation_state["event_id"] = event_id
            mutation_state["reason"] = reason
            mutation_state["confidence"] = confidence
        return result

    @langchain_tool
    def create_event_for_current_packet(
        description: str,
        reason: str,
        confidence: float,
    ) -> str:
        """Create an event and assign the current packet with metadata."""
        if current_packet_id is None:
            return "No current packet is bound to this tool set."
        if mutation_state["done"]:
            return "A mutating event tool was already called for this packet."
        result = mcp.create_event_and_assign_packet(
            current_packet_id,
            description,
            reason=reason,
            confidence=confidence,
        )
        if "event_id:" in result:
            mutation_state["done"] = True
            mutation_state["action"] = "created"
            mutation_state["event_id"] = _parse_event_id(result)
            mutation_state["reason"] = reason
            mutation_state["confidence"] = confidence
        return result

    @langchain_tool
    def update_event_description(event_id: int, description: str) -> str:
        """Refine the assigned event description when new packet evidence helps."""
        if not mutation_state.get("done"):
            return "Assign or create an event before updating its description."
        if mutation_state.get("event_id") != event_id:
            return "You may only update the event assigned to the current packet."
        result = mcp.update_event_description(event_id, description)
        if result.strip().lower() == "ok":
            mutation_state["updated_description"] = description
        return result

    tools = [
        get_packet_info,
        get_full_payload,
        get_surrounding_packets,
        get_conversation_packets,
        get_packets_in_time_window,
    ]
    if current_packet_id is not None:
        tools.extend(
            [
                get_matching_events,
                assign_current_packet_to_event,
                create_event_for_current_packet,
                update_event_description,
            ]
        )
    return tools


def _parse_event_id(text: str) -> Optional[int]:
    """Extract event_id from MCP create output."""

    match = re.search(r"\bevent_id:(\d+)\b", text)
    return int(match.group(1)) if match else None
