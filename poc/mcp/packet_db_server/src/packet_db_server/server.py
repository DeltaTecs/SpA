from __future__ import annotations

import logging
import os

try:
    from psycopg2.extras import RealDictCursor
except ImportError as e:  # pragma: no cover
    raise RuntimeError("psycopg2-binary is required") from e

try:
    from mcp.server.fastmcp import FastMCP
    from mcp.server.fastmcp.server import TransportSecuritySettings
except ImportError as e:  # pragma: no cover
    raise RuntimeError("mcp package is required") from e

from .config import DbConfig
from .db import retry_connect_db
from .event_queries import (
    assign_packet_to_event_record,
    create_event_record,
    events_for_recording_text,
)
from .formatters import hexdump
from .packet_queries import (
    conversation_packets_text,
    list_packet_ids_text,
    packet_info_text_for_packet,
    packets_in_time_window_text,
    payload_hexdump_for_packet,
)


__all__ = [
    "DbConfig",
    "assign_packet_to_event",
    "conversation_packets",
    "create_event",
    "events_for_recording",
    "hexdump",
    "list_packet_ids",
    "main",
    "packet_info",
    "packet_payload_hexdump",
    "packets_in_time_window",
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

    with retry_connect_db() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            return packet_info_text_for_packet(cursor, packet_id)


@mcp.tool()
def packet_payload_hexdump(packet_id: int) -> str:
    """Return full cleartext application payload as hex+ASCII hexdump."""

    with retry_connect_db() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            return payload_hexdump_for_packet(cursor, packet_id)


@mcp.tool()
def list_packet_ids(recording_id: int) -> str:
    """Return all packet IDs for a recording, ordered by packet number."""

    with retry_connect_db() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            return list_packet_ids_text(cursor, recording_id)


@mcp.tool()
def conversation_packets(
    conversation_id: int,
    packet_id: int = 0,
    before: int = 5,
    after: int = 5,
) -> str:
    """Return packet facts for packets in the same conversation."""

    with retry_connect_db() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            return conversation_packets_text(
                cursor,
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

    with retry_connect_db() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            return packets_in_time_window_text(
                cursor,
                recording_id,
                start_ms,
                end_ms,
                max_packets=max_packets,
            )


@mcp.tool()
def events_for_recording(recording_id: int) -> str:
    """Return all events currently associated with packets in this recording."""

    with retry_connect_db() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            return events_for_recording_text(cursor, recording_id)


@mcp.tool()
def create_event(description: str) -> str:
    """Create a new event and return its ID."""

    with retry_connect_db() as conn:
        with conn.cursor() as cursor:
            return create_event_record(cursor, description)


@mcp.tool()
def assign_packet_to_event(packet_id: int, event_id: int) -> str:
    """Assign a packet to an event and widen the event time range."""

    with retry_connect_db() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            return assign_packet_to_event_record(cursor, packet_id, event_id)


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
