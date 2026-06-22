from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Optional

try:
    from psycopg2.extras import RealDictCursor
except ImportError as e:  # pragma: no cover
    raise RuntimeError("psycopg2-binary is required") from e

from .db import retry_connect_db
from .packet_queries import (
    conversation_packets_text,
    list_packet_ids_text,
    packet_info_text_for_packet,
    packets_in_time_window_text,
    payload_hexdump_for_packet,
)


@dataclass(frozen=True)
class PacketAnalysisMetadata:
    """Structured packet facts needed by non-MCP analysis code."""

    packet_id: int
    timestamp_offset_ms: Optional[int]
    has_clear_application_payload: bool
    has_http_header: bool


class DatabaseAccess:
    """Own database connection/cursor handling for MCP tool reads and writes."""

    def __init__(self, connect: Callable[[], Any] = retry_connect_db) -> None:
        self._connect = connect

    def read(
        self,
        query: Callable[..., str],
        *args: Any,
        cursor_factory: Any = RealDictCursor,
        **kwargs: Any,
    ) -> str:
        """Run a read query helper with an isolated database cursor."""

        return self._run(query, *args, cursor_factory=cursor_factory, **kwargs)

    def write(
        self,
        command: Callable[..., str],
        *args: Any,
        cursor_factory: Any = RealDictCursor,
        **kwargs: Any,
    ) -> str:
        """Run a write query helper with an isolated database cursor."""

        return self._run(command, *args, cursor_factory=cursor_factory, **kwargs)

    def packet_info(self, packet_id: int) -> str:
        return self.read(packet_info_text_for_packet, packet_id)

    def packet_payload_hexdump(self, packet_id: int) -> str:
        return self.read(payload_hexdump_for_packet, packet_id)

    def list_packet_ids(self, recording_id: int) -> str:
        return self.read(list_packet_ids_text, recording_id)

    def packet_ids_for_recording(self, recording_id: int) -> list[int]:
        return self.read_rows(_packet_ids_for_recording, recording_id)

    def packet_analysis_metadata(
        self,
        packet_id: int,
    ) -> Optional[PacketAnalysisMetadata]:
        return self.read_row(_packet_analysis_metadata, packet_id)

    def packet_analysis_metadata_for_recording(
        self,
        recording_id: int,
    ) -> list[PacketAnalysisMetadata]:
        return self.read_rows(_packet_analysis_metadata_for_recording, recording_id)

    def conversation_packets(
        self,
        conversation_id: int,
        packet_id: int = 0,
        before: int = 5,
        after: int = 5,
    ) -> str:
        return self.read(
            conversation_packets_text,
            conversation_id,
            packet_id=packet_id,
            before=before,
            after=after,
        )

    def packets_in_time_window(
        self,
        recording_id: int,
        start_ms: int,
        end_ms: int,
        max_packets: int = 40,
    ) -> str:
        return self.read(
            packets_in_time_window_text,
            recording_id,
            start_ms,
            end_ms,
            max_packets=max_packets,
        )

    def read_rows(
        self,
        query: Callable[..., list[Any]],
        *args: Any,
        cursor_factory: Any = RealDictCursor,
        **kwargs: Any,
    ) -> list[Any]:
        """Run a structured read query that returns multiple values."""

        return self._run(query, *args, cursor_factory=cursor_factory, **kwargs)

    def read_row(
        self,
        query: Callable[..., Any],
        *args: Any,
        cursor_factory: Any = RealDictCursor,
        **kwargs: Any,
    ) -> Any:
        """Run a structured read query that returns one value or None."""

        return self._run(query, *args, cursor_factory=cursor_factory, **kwargs)

    def _run(
        self,
        operation: Callable[..., Any],
        *args: Any,
        cursor_factory: Any = RealDictCursor,
        **kwargs: Any,
    ) -> Any:
        with self._connect() as conn:
            if cursor_factory is None:
                with conn.cursor() as cursor:
                    return operation(cursor, *args, **kwargs)

            with conn.cursor(cursor_factory=cursor_factory) as cursor:
                return operation(cursor, *args, **kwargs)


def _packet_ids_for_recording(cursor, recording_id: int) -> list[int]:
    cursor.execute(
        """
        SELECT packet_id
        FROM packet
        WHERE recording_id = %s
        ORDER BY number ASC
        """,
        (recording_id,),
    )
    return [int(row["packet_id"]) for row in cursor.fetchall() or []]


def _packet_analysis_metadata(
    cursor,
    packet_id: int,
) -> Optional[PacketAnalysisMetadata]:
    cursor.execute(
        """
        SELECT
            p.packet_id,
            CASE
                WHEN p.timestamp IS NULL OR recording_bounds.start_timestamp IS NULL
                THEN NULL
                ELSE p.timestamp - recording_bounds.start_timestamp
            END AS timestamp_offset_ms,
            COALESCE(OCTET_LENGTH(p.clear_application_payload), 0) > 0
                AS has_clear_application_payload,
            EXISTS (
                SELECT 1
                FROM packet_header_information phi
                JOIN http_header_information hh
                  ON hh.header_information_id = phi.header_information_id
                WHERE phi.packet_id = p.packet_id
            ) AS has_http_header
        FROM packet p
        LEFT JOIN LATERAL (
            SELECT MIN(timestamp) AS start_timestamp
            FROM packet
            WHERE recording_id = p.recording_id
        ) recording_bounds ON TRUE
        WHERE p.packet_id = %s
        """,
        (packet_id,),
    )
    row = cursor.fetchone()
    if not row:
        return None

    offset = row["timestamp_offset_ms"]
    return PacketAnalysisMetadata(
        packet_id=int(row["packet_id"]),
        timestamp_offset_ms=int(offset) if offset is not None else None,
        has_clear_application_payload=bool(row["has_clear_application_payload"]),
        has_http_header=bool(row["has_http_header"]),
    )


def _packet_analysis_metadata_for_recording(
    cursor,
    recording_id: int,
) -> list[PacketAnalysisMetadata]:
    cursor.execute(
        """
        WITH recording_bounds AS (
            SELECT MIN(timestamp) AS start_timestamp
            FROM packet
            WHERE recording_id = %s
        )
        SELECT
            p.packet_id,
            CASE
                WHEN p.timestamp IS NULL OR recording_bounds.start_timestamp IS NULL
                THEN NULL
                ELSE p.timestamp - recording_bounds.start_timestamp
            END AS timestamp_offset_ms,
            COALESCE(OCTET_LENGTH(p.clear_application_payload), 0) > 0
                AS has_clear_application_payload,
            EXISTS (
                SELECT 1
                FROM packet_header_information phi
                JOIN http_header_information hh
                  ON hh.header_information_id = phi.header_information_id
                WHERE phi.packet_id = p.packet_id
            ) AS has_http_header
        FROM packet p
        CROSS JOIN recording_bounds
        WHERE p.recording_id = %s
        ORDER BY p.number ASC
        """,
        (recording_id, recording_id),
    )

    metadata: list[PacketAnalysisMetadata] = []
    for row in cursor.fetchall() or []:
        offset = row["timestamp_offset_ms"]
        metadata.append(
            PacketAnalysisMetadata(
                packet_id=int(row["packet_id"]),
                timestamp_offset_ms=int(offset) if offset is not None else None,
                has_clear_application_payload=bool(
                    row["has_clear_application_payload"]
                ),
                has_http_header=bool(row["has_http_header"]),
            )
        )
    return metadata


database = DatabaseAccess()
