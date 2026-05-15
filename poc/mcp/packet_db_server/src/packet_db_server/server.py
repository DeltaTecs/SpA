from __future__ import annotations

import logging
import os

try:
    from mcp.server.fastmcp import FastMCP
    from mcp.server.fastmcp.server import TransportSecuritySettings
except ImportError as e:  # pragma: no cover
    raise RuntimeError("mcp package is required") from e

from .config import DbConfig
from .database_access import DatabaseAccess, database
from .formatters import hexdump


__all__ = [
    "DbConfig",
    "DatabaseAccess",
    "assign_packet_to_event",
    "conversation_packets",
    "create_event",
    "create_event_and_assign_packet",
    "database",
    "event_packets",
    "events",
    "events_for_recording",
    "hexdump",
    "list_packet_ids",
    "main",
    "packet_info",
    "packet_payload_hexdump",
    "packets_in_time_window",
    "update_event_description",
]


_mcp_host = os.environ.get("MCP_HOST", "0.0.0.0")
_mcp_port = int(os.environ.get("MCP_PORT", "8765"))

mcp = FastMCP(
    "packet-db",
    host=_mcp_host,
    port=_mcp_port,
    # Docker peers connect by service name (for example mcp-packet-db:8765).
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=False
    ),
)


@mcp.tool()
def packet_info(packet_id: int) -> str:
    """Return flow, protocol, and preview payload info for a packet."""

    return database.packet_info(packet_id)


@mcp.tool()
def packet_payload_hexdump(packet_id: int) -> str:
    """Return full cleartext application payload as hex+ASCII hexdump."""

    return database.packet_payload_hexdump(packet_id)


@mcp.tool()
def list_packet_ids(recording_id: int) -> str:
    """Return all packet IDs for a recording, ordered by packet number."""

    return database.list_packet_ids(recording_id)


@mcp.tool()
def conversation_packets(
    conversation_id: int,
    packet_id: int = 0,
    before: int = 5,
    after: int = 5,
) -> str:
    """Return packet facts for packets in the same conversation."""

    return database.conversation_packets(
        conversation_id,
        packet_id=packet_id,
        before=before,
        after=after,
    )


@mcp.tool()
def packets_in_time_window(
    recording_id: int,
    start_ms: int,
    end_ms: int,
    max_packets: int = 40,
) -> str:
    """Return packet facts for a recording time window."""

    return database.packets_in_time_window(
        recording_id,
        start_ms,
        end_ms,
        max_packets=max_packets,
    )


@mcp.tool()
def events_for_recording(recording_id: int, packet_id: int = 0) -> str:
    """Return recording events, optionally filtered by packet IP/port tuple."""

    return database.events_for_recording(recording_id, packet_id=packet_id)


@mcp.tool()
def events() -> str:
    """Return all persisted events with packet counts and recording IDs."""

    return database.events()


@mcp.tool()
def event_packets(event_id: int) -> str:
    """Return event metadata and packet IDs assigned to the event."""

    return database.event_packets(event_id)


@mcp.tool()
def create_event(description: str) -> str:
    """Create a new event and return its ID."""

    return database.create_event(description)


@mcp.tool()
def create_event_and_assign_packet(
    packet_id: int,
    description: str,
    reason: str = "",
    confidence: float | None = None,
) -> str:
    """Create an event and assign one packet with LLM rationale metadata."""

    return database.create_event_and_assign_packet(
        packet_id,
        description,
        reason=reason,
        confidence=confidence,
    )


@mcp.tool()
def assign_packet_to_event(
    packet_id: int,
    event_id: int,
    reason: str = "",
    confidence: float | None = None,
) -> str:
    """Assign a packet to an event with LLM rationale metadata."""

    return database.assign_packet_to_event(
        packet_id,
        event_id,
        reason=reason,
        confidence=confidence,
    )


@mcp.tool()
def update_event_description(event_id: int, description: str) -> str:
    """Update an event description after new packets clarify the event."""

    return database.update_event_description(event_id, description)


def main() -> None:
    transport = os.environ.get("MCP_TRANSPORT", "sse").lower()
    logger_srv = logging.getLogger(__name__)
    logger_srv.info(
        "Starting MCP server (transport=%s, host=%s, port=%d)",
        transport,
        _mcp_host,
        _mcp_port,
    )
    mcp.run(transport=transport)


if __name__ == "__main__":
    main()
