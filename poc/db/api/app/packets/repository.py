from __future__ import annotations

import base64
from dataclasses import dataclass, replace
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..db import dict_cursor
from ..http_parsing import parse_http_header


_APPLICATION_PROTOCOL_NAMES = (
    "DNS",
    "TLS",
    "QUIC",
    "DTLS",
    "STUN",
    "TURN",
    "RTP",
    "RTCP",
    "HTTP",
    "Websocket",
)
_APP_PROTOCOL_BY_FILTER = {
    "http": "HTTP",
    "websocket": "Websocket",
}
_OTHER_APPLICATION_PROTOCOL_NAMES = tuple(
    name
    for name in _APPLICATION_PROTOCOL_NAMES
    if name not in _APP_PROTOCOL_BY_FILTER.values()
)

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
    has_clear_payload: Optional[bool] = None
    has_http_header_text: Optional[bool] = None
    app_protocol: Optional[str] = None
    start_ms: Optional[int] = None
    end_ms: Optional[int] = None
    limit: int = 100
    offset: int = 0
    # Resolved from ``protocol`` against the protocol table; not set by callers.
    _protocol_id: Optional[int] = None
    _app_protocol_id: Optional[int] = None
    _other_app_protocol_ids: Tuple[int, ...] = ()
    _excluded_app_protocol_ids: Tuple[int, ...] = ()


class PacketRepository:
    """Read access to the ``packet`` table and its related header rows.

    Each public method owns its own short-lived cursor, keeping query logic in
    one cohesive place as the surface grows.
    """

    def list_packets(self, filters: PacketFilters) -> Tuple[List[Dict[str, Any]], int]:
        """Return matching packet summaries and the total count for the filters."""
        with dict_cursor() as cursor:
            filters = _resolve_protocol_filters(cursor, filters)
            if filters is None:
                return [], 0

            where, params = _build_where(filters)
            total = _count_packets(cursor, where, params)
            rows = _select_packets(cursor, where, params, filters.limit, filters.offset)
            return rows, total

    def get_packet(self, packet_id: int) -> Optional[Dict[str, Any]]:
        """Return one packet with parsed headers, or ``None`` if it is absent."""
        with dict_cursor() as cursor:
            packet = _select_packet_by_id(cursor, packet_id)
            if packet is None:
                return None
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
    if filters.has_clear_payload is not None:
        operator = ">" if filters.has_clear_payload else "="
        clauses.append(
            f"COALESCE(OCTET_LENGTH(p.clear_application_payload), 0) {operator} 0"
        )
    if filters.has_http_header_text is not None:
        condition = _non_empty_http_header_text_condition()
        if filters.has_http_header_text:
            clauses.append(condition)
        else:
            clauses.append(f"NOT {condition}")
    if filters._app_protocol_id is not None:
        clauses.append("p.protocol_ids @> ARRAY[%s]::bigint[]")
        params.append(filters._app_protocol_id)
    if filters._other_app_protocol_ids:
        clauses.append(_protocol_overlap_condition(filters._other_app_protocol_ids))
        params.extend(filters._other_app_protocol_ids)
    if filters._excluded_app_protocol_ids:
        clauses.append(
            f"NOT ({_protocol_overlap_condition(filters._excluded_app_protocol_ids)})"
        )
        params.extend(filters._excluded_app_protocol_ids)
    if filters.start_ms is not None:
        clauses.append("p.timestamp >= %s")
        params.append(filters.start_ms)
    if filters.end_ms is not None:
        clauses.append("p.timestamp <= %s")
        params.append(filters.end_ms)

    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, params


def _resolve_protocol_filters(cursor, filters: PacketFilters) -> Optional[PacketFilters]:
    if filters.protocol:
        protocol_id = _protocol_id_for_name(cursor, filters.protocol)
        if protocol_id is None:
            # Unknown protocol name: nothing can match.
            return None
        filters = replace(filters, _protocol_id=protocol_id)

    if not filters.app_protocol:
        return filters

    app_protocol = filters.app_protocol.lower()
    protocol_name = _APP_PROTOCOL_BY_FILTER.get(app_protocol)
    if protocol_name:
        protocol_id = _protocol_id_for_name(cursor, protocol_name)
        if protocol_id is None:
            return None
        return replace(filters, _app_protocol_id=protocol_id)

    if app_protocol != "other":
        return None

    other_ids = tuple(_protocol_ids_for_names(cursor, _OTHER_APPLICATION_PROTOCOL_NAMES))
    if not other_ids:
        return None

    excluded_ids = tuple(_protocol_ids_for_names(cursor, _APP_PROTOCOL_BY_FILTER.values()))
    return replace(
        filters,
        _other_app_protocol_ids=other_ids,
        _excluded_app_protocol_ids=excluded_ids,
    )


def _non_empty_http_header_text_condition() -> str:
    return """
        EXISTS (
            SELECT 1
            FROM packet_header_information phi_http_filter
            JOIN http_header_information hh_filter
              ON hh_filter.header_information_id = phi_http_filter.header_information_id
            WHERE phi_http_filter.packet_id = p.packet_id
              AND NULLIF(BTRIM(hh_filter.text_header), '') IS NOT NULL
        )
    """


def _protocol_overlap_condition(protocol_ids: Tuple[int, ...]) -> str:
    placeholders = ", ".join(["%s"] * len(protocol_ids))
    return f"p.protocol_ids && ARRAY[{placeholders}]::bigint[]"


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
        SELECT src_port, dst_port, transport_protocol FROM (
            SELECT th.src_port, th.dst_port, 'TCP' AS transport_protocol, 1 AS priority
            FROM tcp_header_information th
            JOIN packet_header_information phi
              ON th.header_information_id = phi.header_information_id
            WHERE phi.packet_id = p.packet_id
            UNION ALL
            SELECT uh.src_port, uh.dst_port, 'UDP' AS transport_protocol, 2 AS priority
            FROM udp_header_information uh
            JOIN packet_header_information phi
              ON uh.header_information_id = phi.header_information_id
            WHERE phi.packet_id = p.packet_id
        ) ports_any
        ORDER BY priority
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

_PACKET_ENRICH_SELECT_COLUMNS = f"""
    {_PACKET_SELECT_COLUMNS},
    ip.src_addr AS ip_src,
    ip.dst_addr AS ip_dst,
    ports.src_port AS port_src,
    ports.dst_port AS port_dst,
    ports.transport_protocol AS transport_protocol,
    http.text_header AS http_text,
    http.stream_id AS http_stream_id,
    http.http_count AS http_count
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
            {_PACKET_ENRICH_SELECT_COLUMNS}
        FROM packet p
        {_PACKET_ENRICH_JOINS}
        {where}
        ORDER BY p.timestamp ASC NULLS LAST, p.number ASC, p.packet_id ASC
        LIMIT %s OFFSET %s
        """,
        [*params, limit, offset],
    )
    return [_enrich_row(dict(row)) for row in cursor.fetchall() or []]


def _select_packet_by_id(cursor, packet_id: int) -> Optional[Dict[str, Any]]:
    cursor.execute(
        f"""
        SELECT
            {_PACKET_ENRICH_SELECT_COLUMNS}
        FROM packet p
        {_PACKET_ENRICH_JOINS}
        WHERE p.packet_id = %s
        """,
        (packet_id,),
    )
    row = cursor.fetchone()
    return _enrich_row(dict(row)) if row is not None else None


def _enrich_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """Fold the raw header columns into peer ip/ports, an http summary and a key."""
    from_local = row.get("from_local")
    ip_src, ip_dst = row.pop("ip_src", None), row.pop("ip_dst", None)
    port_src, port_dst = row.pop("port_src", None), row.pop("port_dst", None)
    transport_protocol = row.pop("transport_protocol", None)

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
            "status_code": parsed.status_code,
            "status_text": parsed.status_text,
            "stream_id": stream_id,
        }
    else:
        row["http"] = None

    row["association_key"] = _association_key(
        row["packet_id"],
        transport_protocol,
        ip_src,
        port_src,
        ip_dst,
        port_dst,
        stream_id,
    )
    return row


def _association_key(
    packet_id: int,
    transport_protocol: Optional[str],
    src_ip: Optional[str],
    src_port: Optional[int],
    dst_ip: Optional[str],
    dst_port: Optional[int],
    stream_id: Optional[int],
) -> str:
    """Stable grouping key for the explorer color toggle.

    Packets in the same transport flow share a key. Endpoint order is normalized
    so both directions of a TCP/UDP exchange get the same color. When an HTTP
    stream id is present, the key is split further so multiplexed streams within
    the same flow stay visually distinct. Packets without a complete IP/port
    tuple fall back to their own id instead of being grouped accidentally.
    """
    base = _flow_key(transport_protocol, src_ip, src_port, dst_ip, dst_port)
    if base is None:
        base = f"pkt:{packet_id}"
    if stream_id is not None:
        base += f"|stream:{stream_id}"
    return base


def _flow_key(
    transport_protocol: Optional[str],
    src_ip: Optional[str],
    src_port: Optional[int],
    dst_ip: Optional[str],
    dst_port: Optional[int],
) -> Optional[str]:
    """Return a normalized TCP/UDP 5-tuple key, or ``None`` if incomplete."""
    if (
        transport_protocol is None
        or not src_ip
        or not dst_ip
        or src_port is None
        or dst_port is None
    ):
        return None

    protocol = transport_protocol.upper()
    first = (src_ip, int(src_port))
    second = (dst_ip, int(dst_port))
    if first > second:
        first, second = second, first

    return (
        f"flow:{protocol}|"
        f"{_format_endpoint(first[0], first[1])}|"
        f"{_format_endpoint(second[0], second[1])}"
    )


def _format_endpoint(ip_address: str, port: int) -> str:
    return f"[{ip_address}]:{port}"


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


def _protocol_ids_for_names(cursor, names: Iterable[str]) -> List[int]:
    names = list(names)
    if not names:
        return []

    placeholders = ", ".join(["%s"] * len(names))
    cursor.execute(
        f"SELECT protocol_id FROM protocol WHERE name IN ({placeholders})",
        names,
    )
    return [int(row["protocol_id"]) for row in cursor.fetchall() or []]


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
