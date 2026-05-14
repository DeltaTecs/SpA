from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Dict, Optional

from mcp_client import MCPClient
from scanner_models import EventContext, EventPacket, PacketFact
from user_context import UserAction, format_user_context


logger = logging.getLogger(__name__)

MAX_INITIAL_PACKET_INFOS = 80


@dataclass
class PreparedEventContext:
    event: EventContext
    recording_id: int
    event_packets_text: str
    facts: Dict[int, PacketFact]
    event_start_offset_ms: Optional[int]
    event_end_offset_ms: Optional[int]
    text: str

    def external_context(
        self,
        app_details: Optional[str],
        user_actions: Optional[list[UserAction]],
    ) -> str:
        return format_user_context(
            app_details,
            user_actions,
            self.event_start_offset_ms,
            self.event_end_offset_ms,
        )


def load_prepared_event_context(
    mcp_client: MCPClient,
    event_id: int,
) -> PreparedEventContext:
    event_packets_text = mcp_client.event_packets(event_id)
    if re.search(rf"^event_id {event_id} not found$", event_packets_text.strip()):
        raise RuntimeError(event_packets_text.strip())

    event = parse_event_packets(event_packets_text)
    if not event.packets:
        raise RuntimeError(f"event_id {event_id} has no assigned packets")

    recording_id = event.primary_recording_id
    if recording_id is None:
        raise RuntimeError(f"event_id {event_id} has no recording_id")
    if len(event.recording_ids) > 1:
        logger.warning(
            "Event %d spans multiple recordings %s; using recording %d for time-window tools",
            event_id,
            event.recording_ids,
            recording_id,
        )

    facts = load_packet_facts(mcp_client, event)
    event_start_offset_ms, event_end_offset_ms = event_offsets(facts)
    text = format_event_context(
        event=event,
        event_packets_text=event_packets_text,
        facts=facts,
        recording_id=recording_id,
        event_start_offset_ms=event_start_offset_ms,
        event_end_offset_ms=event_end_offset_ms,
    )
    return PreparedEventContext(
        event=event,
        recording_id=recording_id,
        event_packets_text=event_packets_text,
        facts=facts,
        event_start_offset_ms=event_start_offset_ms,
        event_end_offset_ms=event_end_offset_ms,
        text=text,
    )


def parse_event_packets(text: str) -> EventContext:
    header_match = re.search(
        r"^event_id:(\d+)\s+description:(.*?)\s+start:([^\s]+)\s+end:([^\s]+)\s*$",
        text,
        flags=re.MULTILINE,
    )
    if not header_match:
        raise ValueError(f"Could not parse event metadata: {text[:200]}")

    packets: list[EventPacket] = []
    for match in re.finditer(
        r"^packet_id:(\d+)\s+recording_id:(\d+)\s+number:([^\s]+)\s+"
        r"timestamp:([^\s]+)\s+conversation_id:([^\s]+)\s*$",
        text,
        flags=re.MULTILINE,
    ):
        packets.append(
            EventPacket(
                packet_id=int(match.group(1)),
                recording_id=int(match.group(2)),
                number=parse_nullable_int(match.group(3)),
                timestamp=parse_nullable_int(match.group(4)),
                conversation_id=parse_nullable_int(match.group(5)),
            )
        )

    return EventContext(
        event_id=int(header_match.group(1)),
        description=header_match.group(2).strip(),
        start_timestamp=parse_nullable_int(header_match.group(3)),
        end_timestamp=parse_nullable_int(header_match.group(4)),
        packets=packets,
    )


def load_packet_facts(
    mcp_client: MCPClient,
    event: EventContext,
) -> Dict[int, PacketFact]:
    facts: Dict[int, PacketFact] = {}
    for packet in event.packets:
        try:
            text = mcp_client.packet_info(packet.packet_id)
        except Exception as exc:
            logger.error("Failed to fetch packet_info for %d: %s", packet.packet_id, exc)
            continue

        offset_match = re.search(
            r"^timestamp offset:\s*(-?\d+)\s+ms",
            text,
            flags=re.MULTILINE,
        )
        conversation_match = re.search(
            r"^conversation_id:\s*(\d+)\s*$",
            text,
            flags=re.MULTILINE,
        )
        facts[packet.packet_id] = PacketFact(
            packet_id=packet.packet_id,
            timestamp=packet.timestamp,
            offset_ms=int(offset_match.group(1)) if offset_match else None,
            conversation_id=(
                int(conversation_match.group(1))
                if conversation_match
                else packet.conversation_id
            ),
            text=text,
        )
    return facts


def event_offsets(facts: Dict[int, PacketFact]) -> tuple[Optional[int], Optional[int]]:
    offsets = [fact.offset_ms for fact in facts.values() if fact.offset_ms is not None]
    if not offsets:
        return None, None
    return min(offsets), max(offsets)


def format_event_context(
    *,
    event: EventContext,
    event_packets_text: str,
    facts: Dict[int, PacketFact],
    recording_id: int,
    event_start_offset_ms: Optional[int],
    event_end_offset_ms: Optional[int],
) -> str:
    packet_ids = ", ".join(str(packet_id) for packet_id in event.packet_ids)
    offset_text = "(unknown)"
    if event_start_offset_ms is not None and event_end_offset_ms is not None:
        offset_text = f"{event_start_offset_ms}..{event_end_offset_ms} ms"

    parts = [
        "=== Event Under Review ===",
        f"event_id: {event.event_id}",
        f"description: {event.description or '(none)'}",
        f"primary recording_id: {recording_id}",
        f"recording-relative event offset: {offset_text}",
        f"assigned packet IDs: {packet_ids}",
        "",
        "=== event_packets MCP Output ===",
        event_packets_text,
        "",
        "=== Initial Packet Facts ===",
    ]

    included = 0
    for packet_id in event.packet_ids:
        fact = facts.get(packet_id)
        if fact is None:
            continue
        parts.append(f"--- packet_id:{packet_id} ---")
        parts.append(fact.text)
        included += 1
        if included >= MAX_INITIAL_PACKET_INFOS:
            remaining = len(event.packet_ids) - included
            if remaining > 0:
                parts.append(
                    f"(omitted {remaining} additional event packets; use packet_info if needed)"
                )
            break

    parts.append("")
    parts.append(
        "Use the tools if you need surrounding conversation packets, full payloads, "
        "or traffic around the event/user-action time window."
    )
    return "\n".join(parts)


def parse_nullable_int(value: str) -> Optional[int]:
    if value in {"", "None", "none", "NULL", "null"}:
        return None
    try:
        return int(value)
    except ValueError:
        return None
