from __future__ import annotations

import base64
from dataclasses import dataclass, replace
from typing import Any, Dict, List, Optional, Tuple

from ..db import dict_cursor
from ..http_parsing import parse_http_header


# Core packet columns shared by the summary/detail selects. Kept in one place so
# the list and single-packet queries stay in sync.
_PACKET_SELECT_COLUMNS = """
    p.packet_id,
    p.recording_id,
    p.conversation_id,
    p.from_local,
    p.timestamp,
    p.number,
    p.entropy,
    COALESCE(OCTET_LENGTH(p.clear_application_payload), 0) AS payload_length,
    COALESCE(
        (
            SELECT array_agg(pr.name ORDER BY u.ord)
            FROM unnest(p.protocol_ids) WITH ORDINALITY AS u(protocol_id, ord)
            JOIN protocol pr ON pr.protocol_id = u.protocol_id
        ),
        ARRAY[]::text[]
    ) AS protocols
"""


@dataclass(frozen=True)
class PacketFilters:
    """Optional constraints for :meth:`PacketRepository.list_packets`."""

    recording_id: Optional[int] = None
    conversation_id: Optional[int] = None
    from_local: Optional[bool] = None
    protocol: Optional[str] = None
    start_ms: Optional[int] = None
    end_ms: Optional[int] = None
    limit: int = 100
    offset: int = 0
    # Resolved from ``protocol`` against the protocol table; not set by callers.
    _protocol_id: Optional[int] = None


class PacketRepository:
    """Read access to the ``packet`` table and its related header rows.

    Each public method owns its own short-lived cursor, keeping query logic in
    one cohesive place as the surface grows.
    """

    def list_packets(self, filters: PacketFilters) -> Tuple[List[Dict[str, Any]], int]:
        """Return matching packet summaries and the total count for the filters."""
        with dict_cursor() as cursor:
            if filters.protocol:
                protocol_id = _protocol_id_for_name(cursor, filters.protocol)
                if protocol_id is None:
                    # Unknown protocol name: nothing can match.
                    return [], 0
                filters = replace(filters, _protocol_id=protocol_id)

            where, params = _build_where(filters)
            total = _count_packets(cursor, where, params)
            rows = _select_packets(cursor, where, params, filters.limit, filters.offset)
            return rows, total

    def get_packet(self, packet_id: int) -> Optional[Dict[str, Any]]:
        """Return one packet with parsed headers, or ``None`` if it is absent."""
        with dict_cursor() as cursor:
            cursor.execute(
                f"SELECT {_PACKET_SELECT_COLUMNS} FROM packet p WHERE p.packet_id = %s",
                (packet_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            packet = dict(row)
            packet["headers"] = _select_headers(cursor, packet_id)
            return packet

    def get_payload(self, packet_id: int) -> Optional[Dict[str, Any]]:
        """Return the raw byte fields for a packet, base64-encoded."""
        with dict_cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    packet_id,
                    clear_application_payload,
                    COALESCE(OCTET_LENGTH(clear_application_payload), 0)
                        AS clear_application_payload_length,
                    packet_bytes,
                    COALESCE(OCTET_LENGTH(packet_bytes), 0) AS packet_bytes_length
                FROM packet
                WHERE packet_id = %s
                """,
                (packet_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            return {
                "packet_id": row["packet_id"],
                "encoding": "base64",
                "clear_application_payload": _b64(row["clear_application_payload"]),
                "clear_application_payload_length": row["clear_application_payload_length"],
                "packet_bytes": _b64(row["packet_bytes"]),
                "packet_bytes_length": row["packet_bytes_length"],
            }


def _build_where(filters: PacketFilters) -> Tuple[str, List[Any]]:
    clauses: List[str] = []
    params: List[Any] = []

    if filters.recording_id is not None:
        clauses.append("p.recording_id = %s")
        params.append(filters.recording_id)
    if filters.conversation_id is not None:
        clauses.append("p.conversation_id = %s")
        params.append(filters.conversation_id)
    if filters.from_local is not None:
        clauses.append("p.from_local = %s")
        params.append(filters.from_local)
    if filters._protocol_id is not None:
        # Uses the GIN index on protocol_ids.
        clauses.append("p.protocol_ids @> ARRAY[%s]::bigint[]")
        params.append(filters._protocol_id)
    if filters.start_ms is not None:
        clauses.append("p.timestamp >= %s")
        params.append(filters.start_ms)
    if filters.end_ms is not None:
        clauses.append("p.timestamp <= %s")
        params.append(filters.end_ms)

    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, params


def _count_packets(cursor, where: str, params: List[Any]) -> int:
    cursor.execute(f"SELECT COUNT(*) AS total FROM packet p{where}", params)
    return int(cursor.fetchone()["total"])


# Lateral joins that pull the single most relevant header row per protocol so the
# list can be enriched (peer ip/ports, http summary, grouping key) in one query
# without an N+1 round trip per packet.
_PACKET_ENRICH_JOINS = """
    LEFT JOIN LATERAL (
        SELECT ih.src_addr, ih.dst_addr
        FROM ip_header_information ih
        JOIN packet_header_information phi
          ON ih.header_information_id = phi.header_information_id
        WHERE phi.packet_id = p.packet_id
        LIMIT 1
    ) ip ON true
    LEFT JOIN LATERAL (
        SELECT src_port, dst_port FROM (
            SELECT th.src_port, th.dst_port
            FROM tcp_header_information th
            JOIN packet_header_information phi
              ON th.header_information_id = phi.header_information_id
            WHERE phi.packet_id = p.packet_id
            UNION ALL
            SELECT uh.src_port, uh.dst_port
            FROM udp_header_information uh
            JOIN packet_header_information phi
              ON uh.header_information_id = phi.header_information_id
            WHERE phi.packet_id = p.packet_id
        ) ports_any
        LIMIT 1
    ) ports ON true
    LEFT JOIN LATERAL (
        SELECT
            (array_agg(hh.text_header ORDER BY hh.header_information_id))[1] AS text_header,
            min(hh.stream_id) AS stream_id,
            count(*) AS http_count
        FROM http_header_information hh
        JOIN packet_header_information phi
          ON hh.header_information_id = phi.header_information_id
        WHERE phi.packet_id = p.packet_id
    ) http ON true
"""


def _select_packets(
    cursor,
    where: str,
    params: List[Any],
    limit: int,
    offset: int,
) -> List[Dict[str, Any]]:
    cursor.execute(
        f"""
        SELECT
            {_PACKET_SELECT_COLUMNS},
            ip.src_addr AS ip_src,
            ip.dst_addr AS ip_dst,
            ports.src_port AS port_src,
            ports.dst_port AS port_dst,
            http.text_header AS http_text,
            http.stream_id AS http_stream_id,
            http.http_count AS http_count
        FROM packet p
        {_PACKET_ENRICH_JOINS}
        {where}
        ORDER BY p.timestamp ASC NULLS LAST, p.number ASC, p.packet_id ASC
        LIMIT %s OFFSET %s
        """,
        [*params, limit, offset],
    )
    return [_enrich_row(dict(row)) for row in cursor.fetchall() or []]


def _enrich_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """Fold the raw header columns into peer ip/ports, an http summary and a key."""
    from_local = row.get("from_local")
    ip_src, ip_dst = row.pop("ip_src", None), row.pop("ip_dst", None)
    port_src, port_dst = row.pop("port_src", None), row.pop("port_dst", None)

    # Outbound: peer is the destination. Inbound (or unknown): peer is the source.
    if from_local is True:
        row["remote_ip"], row["remote_port"], row["local_port"] = ip_dst, port_dst, port_src
    else:
        row["remote_ip"], row["remote_port"], row["local_port"] = ip_src, port_src, port_dst
        if from_local is None:
            # Direction unknown; fall back to whichever ip is present.
            row["remote_ip"] = ip_dst or ip_src

    http_text = row.pop("http_text", None)
    stream_id = row.pop("http_stream_id", None)
    http_count = row.pop("http_count", 0) or 0

    if http_count:
        parsed = parse_http_header(http_text)
        row["http"] = {
            "method": parsed.method,
            "host": parsed.host,
            "path": parsed.path,
            "stream_id": stream_id,
        }
    else:
        row["http"] = None

    row["association_key"] = _association_key(
        row.get("conversation_id"), row["packet_id"], http_count, stream_id
    )
    return row


def _association_key(
    conversation_id: Optional[int],
    packet_id: int,
    http_count: int,
    stream_id: Optional[int],
) -> str:
    """Stable grouping key for the explorer color toggle.

    Packets in the same conversation share a key; when an HTTP stream is present
    the key is split further so distinct HTTP streams within a conversation get
    their own color. Packets without a conversation fall back to their own id.
    """
    base = f"conv:{conversation_id}" if conversation_id is not None else f"pkt:{packet_id}"
    if http_count:
        base += f"|stream:{stream_id}" if stream_id is not None else "|http"
    return base


def _select_headers(cursor, packet_id: int) -> Dict[str, Any]:
    headers: Dict[str, Any] = {"ip": None, "tcp": None, "udp": None, "http": []}

    cursor.execute(
        """
        SELECT ih.src_addr, ih.dst_addr
        FROM ip_header_information ih
        JOIN packet_header_information phi
          ON ih.header_information_id = phi.header_information_id
        WHERE phi.packet_id = %s
        """,
        (packet_id,),
    )
    row = cursor.fetchone()
    headers["ip"] = dict(row) if row else None

    cursor.execute(
        """
        SELECT th.src_port, th.dst_port, th.length
        FROM tcp_header_information th
        JOIN packet_header_information phi
          ON th.header_information_id = phi.header_information_id
        WHERE phi.packet_id = %s
        """,
        (packet_id,),
    )
    row = cursor.fetchone()
    headers["tcp"] = dict(row) if row else None

    cursor.execute(
        """
        SELECT uh.src_port, uh.dst_port, uh.length
        FROM udp_header_information uh
        JOIN packet_header_information phi
          ON uh.header_information_id = phi.header_information_id
        WHERE phi.packet_id = %s
        """,
        (packet_id,),
    )
    row = cursor.fetchone()
    headers["udp"] = dict(row) if row else None

    cursor.execute(
        """
        SELECT hh.header_information_id, hh.text_header, hh.stream_id, hh.version
        FROM http_header_information hh
        JOIN packet_header_information phi
          ON hh.header_information_id = phi.header_information_id
        WHERE phi.packet_id = %s
        ORDER BY hh.header_information_id ASC
        """,
        (packet_id,),
    )
    headers["http"] = [dict(r) for r in cursor.fetchall() or []]

    return headers


def _protocol_id_for_name(cursor, name: str) -> Optional[int]:
    cursor.execute(
        "SELECT protocol_id FROM protocol WHERE name = %s",
        (name,),
    )
    row = cursor.fetchone()
    return int(row["protocol_id"]) if row else None


def _b64(value: Any) -> Optional[str]:
    """Encode a psycopg2 ``bytea`` value (memoryview/bytes) as base64 text."""
    if value is None:
        return None
    if isinstance(value, memoryview):
        value = value.tobytes()
    elif isinstance(value, bytearray):
        value = bytes(value)
    elif not isinstance(value, bytes):
        raise TypeError(f"Unexpected bytea type: {type(value)}")
    return base64.b64encode(value).decode("ascii")
