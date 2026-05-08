from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from .formatters import (
    bytes_from_bytea,
    format_packet_info_text,
    guess_app_protocol,
    hexdump,
)


def protocol_names_for_ids(cursor, protocol_ids: Sequence[int]) -> List[str]:
    if not protocol_ids:
        return []

    cursor.execute(
        """
        SELECT u.ord, p.name
        FROM unnest(%s::bigint[]) WITH ORDINALITY AS u(protocol_id, ord)
        JOIN protocol p ON p.protocol_id = u.protocol_id
        ORDER BY u.ord ASC
        """,
        (list(protocol_ids),),
    )
    rows = cursor.fetchall() or []
    if not rows:
        return []

    first = rows[0]
    if isinstance(first, dict):
        return [r.get("name") for r in rows if r.get("name") is not None]

    return [row[1] for row in rows]


def get_headers(cursor, packet_id: int) -> Dict[str, Any]:
    headers: Dict[str, Any] = {"ip": None, "tcp": None, "udp": None, "http": []}

    cursor.execute(
        """
        SELECT ih.src_addr, ih.dst_addr
        FROM ip_header_information ih
        JOIN packet_header_information phi ON ih.header_information_id = phi.header_information_id
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
        JOIN packet_header_information phi ON th.header_information_id = phi.header_information_id
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
        JOIN packet_header_information phi ON uh.header_information_id = phi.header_information_id
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
        JOIN packet_header_information phi ON hh.header_information_id = phi.header_information_id
        WHERE phi.packet_id = %s
        ORDER BY hh.header_information_id ASC
        """,
        (packet_id,),
    )
    http_rows = cursor.fetchall() or []
    headers["http"] = [dict(r) for r in http_rows]

    return headers


def recording_start_timestamp(cursor, recording_id: int) -> Optional[int]:
    cursor.execute(
        """
        SELECT MIN(timestamp) AS start_timestamp
        FROM packet
        WHERE recording_id = %s
        """,
        (recording_id,),
    )
    row = cursor.fetchone()
    if not row:
        return None
    if isinstance(row, dict):
        return row.get("start_timestamp")
    return row[0]


def packet_info_text_for_packet(cursor, packet_id: int) -> str:
    cursor.execute(
        """
        SELECT
            packet_id,
            recording_id,
            conversation_id,
            from_local,
            timestamp,
            number,
            protocol_ids,
            entropy,
            clear_application_payload
        FROM packet
        WHERE packet_id = %s
        """,
        (packet_id,),
    )
    pkt = cursor.fetchone()
    if not pkt:
        return f"packet_id {packet_id} not found"

    protocol_ids = pkt.get("protocol_ids") or []
    protocol_layers = protocol_names_for_ids(cursor, protocol_ids)
    headers = get_headers(cursor, packet_id)

    payload_bytes = bytes_from_bytea(pkt.get("clear_application_payload"))
    http_headers = headers.get("http") or []
    app_protocol = guess_app_protocol(protocol_layers, http_headers)
    recording_id = pkt.get("recording_id")
    recording_start = (
        recording_start_timestamp(cursor, recording_id)
        if recording_id is not None
        else None
    )

    return format_packet_info_text(
        packet_id=packet_id,
        recording_id=recording_id,
        number=pkt.get("number"),
        timestamp=pkt.get("timestamp"),
        recording_start_timestamp=recording_start,
        conversation_id=pkt.get("conversation_id"),
        from_local=pkt.get("from_local"),
        protocol_layers=protocol_layers,
        headers=headers,
        app_protocol=app_protocol,
        entropy=pkt.get("entropy"),
        payload_bytes=payload_bytes,
        payload_preview_bytes=256,
    )


def format_packet_info_list(
    cursor,
    packet_ids: Sequence[int],
    current_packet_id: Optional[int] = None,
) -> str:
    if not packet_ids:
        return "(no packets)"

    parts: List[str] = []
    for packet_id in packet_ids:
        marker = "  <-- current" if current_packet_id is not None and packet_id == current_packet_id else ""
        header = f"=== packet_id:{packet_id}{marker} ==="
        parts.append(f"{header}\n{packet_info_text_for_packet(cursor, packet_id)}")
    return "\n\n".join(parts)


def payload_hexdump_for_packet(cursor, packet_id: int) -> str:
    cursor.execute(
        """
        SELECT packet_id, clear_application_payload
        FROM packet
        WHERE packet_id = %s
        """,
        (packet_id,),
    )
    row = cursor.fetchone()
    if not row:
        return f"packet_id {packet_id} not found"

    payload_bytes = bytes_from_bytea(row.get("clear_application_payload"))
    if not payload_bytes:
        return "(empty)"

    return hexdump(payload_bytes)


def list_packet_ids_text(cursor, recording_id: int) -> str:
    cursor.execute(
        """
        SELECT packet_id, number, timestamp
        FROM packet
        WHERE recording_id = %s
        ORDER BY number ASC
        """,
        (recording_id,),
    )
    rows = cursor.fetchall()
    if not rows:
        return f"No packets found for recording_id {recording_id}"

    lines: List[str] = [f"total: {len(rows)} packets"]
    for row in rows:
        lines.append(
            f"packet_id:{row['packet_id']}  number:{row['number']}  timestamp:{row['timestamp']}"
        )
    return "\n".join(lines)


def conversation_packets_text(
    cursor,
    conversation_id: int,
    packet_id: int = 0,
    before: int = 5,
    after: int = 5,
) -> str:
    before = max(0, min(before, 50))
    after = max(0, min(after, 50))

    cursor.execute(
        """
        SELECT packet_id
        FROM packet
        WHERE conversation_id = %s
        ORDER BY timestamp ASC NULLS LAST, number ASC, packet_id ASC
        """,
        (conversation_id,),
    )
    rows = cursor.fetchall() or []
    ids = [int(r["packet_id"]) for r in rows]
    if not ids:
        return f"No packets found for conversation_id {conversation_id}"

    current_packet_id = packet_id if packet_id in ids else None
    if current_packet_id is not None:
        idx = ids.index(current_packet_id)
        selected = ids[max(0, idx - before) : min(len(ids), idx + after + 1)]
    else:
        limit = max(1, min(before + after + 1, 100))
        selected = ids[:limit]

    return format_packet_info_list(cursor, selected, current_packet_id)


def packets_in_time_window_text(
    cursor,
    recording_id: int,
    start_ms: int,
    end_ms: int,
    max_packets: int = 40,
) -> str:
    if end_ms < start_ms:
        start_ms, end_ms = end_ms, start_ms
    max_packets = max(1, min(max_packets, 100))

    recording_start = recording_start_timestamp(cursor, recording_id)
    if recording_start is None:
        return f"No packets found for recording_id {recording_id}"

    # Treat large inputs as epoch milliseconds; smaller values are offsets.
    epoch_threshold = 1_000_000_000_000
    abs_start = start_ms if start_ms > epoch_threshold else recording_start + start_ms
    abs_end = end_ms if end_ms > epoch_threshold else recording_start + end_ms

    cursor.execute(
        """
        SELECT packet_id
        FROM packet
        WHERE recording_id = %s
          AND timestamp >= %s
          AND timestamp <= %s
        ORDER BY timestamp ASC NULLS LAST, number ASC, packet_id ASC
        LIMIT %s
        """,
        (recording_id, abs_start, abs_end, max_packets),
    )
    rows = cursor.fetchall() or []
    ids = [int(r["packet_id"]) for r in rows]
    if not ids:
        return (
            f"No packets found for recording_id {recording_id} "
            f"in offset window {start_ms}..{end_ms} ms"
        )

    return format_packet_info_list(cursor, ids)
