from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple


def events_text(cursor) -> str:
    """Return all persisted events with packet counts and recording IDs."""
    cursor.execute(
        """
        SELECT
            e.event_id,
            e.description,
            e.start_timestamp,
            e.end_timestamp,
            COUNT(pe.packet_id) AS packet_count,
            ARRAY_REMOVE(ARRAY_AGG(DISTINCT p.recording_id), NULL) AS recording_ids
        FROM event e
        LEFT JOIN packet_event pe ON e.event_id = pe.event_id
        LEFT JOIN packet p ON pe.packet_id = p.packet_id
        GROUP BY e.event_id, e.description, e.start_timestamp, e.end_timestamp
        ORDER BY e.event_id
        """
    )
    rows = cursor.fetchall()
    if not rows:
        return "(no events yet)"

    lines: List[str] = []
    for row in rows:
        recording_ids = ",".join(str(rid) for rid in (row["recording_ids"] or []))
        lines.append(
            f"event_id:{row['event_id']}  description:{row['description']}  "
            f"start:{row['start_timestamp']}  end:{row['end_timestamp']}  "
            f"packets:{row['packet_count']}  recording_ids:{recording_ids}"
        )
    return "\n".join(lines)


def event_packets_text(cursor, event_id: int) -> str:
    """Return event metadata and packets assigned to the event."""
    cursor.execute(
        """
        SELECT event_id, description, start_timestamp, end_timestamp
        FROM event
        WHERE event_id = %s
        """,
        (event_id,),
    )
    event = cursor.fetchone()
    if not event:
        return f"event_id {event_id} not found"

    cursor.execute(
        """
        SELECT
            p.packet_id,
            p.recording_id,
            p.conversation_id,
            p.number,
            p.timestamp
        FROM packet_event pe
        JOIN packet p ON p.packet_id = pe.packet_id
        WHERE pe.event_id = %s
        ORDER BY p.timestamp ASC NULLS LAST, p.number ASC, p.packet_id ASC
        """,
        (event_id,),
    )
    rows = cursor.fetchall() or []

    lines: List[str] = [
        f"event_id:{event['event_id']}  description:{event['description']}  "
        f"start:{event['start_timestamp']}  end:{event['end_timestamp']}",
        f"packets:{len(rows)}",
    ]
    for row in rows:
        conversation_id = (
            row["conversation_id"] if row["conversation_id"] is not None else "null"
        )
        lines.append(
            f"packet_id:{row['packet_id']}  recording_id:{row['recording_id']}  "
            f"number:{row['number']}  timestamp:{row['timestamp']}  "
            f"conversation_id:{conversation_id}"
        )
    return "\n".join(lines)


def events_for_recording_text(
    cursor,
    recording_id: int,
    packet_id: int = 0,
) -> str:
    """Return persisted events, optionally filtered to one packet's flow tuple."""

    ensure_packet_event_metadata_columns(cursor)
    cursor.execute(
        """
        SELECT DISTINCT e.event_id, e.description,
               e.start_timestamp, e.end_timestamp
        FROM event e
        JOIN packet_event pe ON e.event_id = pe.event_id
        JOIN packet p ON pe.packet_id = p.packet_id
        WHERE p.recording_id = %s
        ORDER BY e.event_id
        """,
        (recording_id,),
    )
    rows = cursor.fetchall()
    if not rows:
        return "(no events yet)"

    target_key = None
    if packet_id:
        target_tuple = packet_flow_tuple(cursor, packet_id)
        target_key = normalized_flow_key(target_tuple)
        if target_key is None:
            return f"(no tuple-matchable events for packet_id:{packet_id})"

    lines: List[str] = []
    for row in rows:
        event_packets = event_packet_tuples(cursor, row["event_id"])
        event_keys = {
            key
            for key in (
                normalized_flow_key(packet_tuple) for packet_tuple in event_packets
            )
            if key is not None
        }
        if target_key is not None and event_keys != {target_key}:
            continue

        packet_ids = ", ".join(str(packet["packet_id"]) for packet in event_packets)
        tuple_text = "; ".join(format_packet_tuple(packet) for packet in event_packets)
        lines.append(
            f"event_id:{row['event_id']}  description:{row['description']}  "
            f"start:{row['start_timestamp']}  end:{row['end_timestamp']}  "
            f"packet_ids:{packet_ids or '(none)'}  "
            f"ip_port_tuples:{tuple_text or '(none)'}"
        )

    if lines:
        return "\n".join(lines)
    if packet_id:
        return f"(no events match packet_id:{packet_id} tuple)"
    return "(no events yet)"


def create_event_record(cursor, description: str) -> str:
    """Create an event without assigning packets."""
    cursor.execute(
        """
        INSERT INTO event (description, start_timestamp, end_timestamp)
        VALUES (%s, 0, 0)
        RETURNING event_id
        """,
        (description,),
    )
    event_id = cursor.fetchone()[0]
    return f"event_id:{event_id}"


def create_event_and_assign_packet_record(cursor, packet_id: int, description: str) -> str:
    """Atomically create an event and assign one packet to avoid orphans."""
    return create_event_and_assign_packet_with_metadata_record(
        cursor,
        packet_id,
        description,
        reason="",
        confidence=None,
    )


def create_event_and_assign_packet_with_metadata_record(
    cursor,
    packet_id: int,
    description: str,
    reason: str = "",
    confidence: Optional[float] = None,
) -> str:
    """Atomically create an event and persist assignment metadata."""

    ensure_packet_event_metadata_columns(cursor)
    clean_reason = normalize_reason(reason)
    clean_confidence = normalize_confidence(confidence)
    cursor.execute(
        """
        -- No row is inserted into event if the packet_id does not exist.
        WITH pkt AS (
            SELECT packet_id, timestamp
            FROM packet
            WHERE packet_id = %s
        ),
        new_event AS (
            INSERT INTO event (description, start_timestamp, end_timestamp)
            SELECT %s, timestamp, timestamp
            FROM pkt
            RETURNING event_id
        ),
        assignment AS (
            INSERT INTO packet_event (packet_id, event_id, reason, confidence)
            SELECT pkt.packet_id, new_event.event_id, %s, %s
            FROM pkt
            CROSS JOIN new_event
            RETURNING event_id
        )
        SELECT event_id
        FROM assignment
        """,
        (packet_id, description, clean_reason, clean_confidence),
    )
    row = cursor.fetchone()
    if not row:
        return f"packet_id {packet_id} not found"

    if isinstance(row, dict):
        event_id = row["event_id"]
    else:
        event_id = row[0]
    return f"event_id:{event_id}"


def assign_packet_to_event_record(
    cursor,
    packet_id: int,
    event_id: int,
    reason: str = "",
    confidence: Optional[float] = None,
) -> str:
    """Assign an existing packet to an event and persist assignment metadata."""

    ensure_packet_event_metadata_columns(cursor)
    clean_reason = normalize_reason(reason)
    clean_confidence = normalize_confidence(confidence)
    cursor.execute(
        "SELECT timestamp FROM packet WHERE packet_id = %s",
        (packet_id,),
    )
    pkt = cursor.fetchone()
    if not pkt:
        return f"packet_id {packet_id} not found"

    cursor.execute("SELECT event_id FROM event WHERE event_id = %s", (event_id,))
    if not cursor.fetchone():
        return f"event_id {event_id} not found"

    mismatch = event_tuple_mismatch(cursor, packet_id, event_id)
    if mismatch:
        return mismatch

    ts = pkt["timestamp"]

    cursor.execute(
        """
        INSERT INTO packet_event (packet_id, event_id, reason, confidence)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (packet_id, event_id) DO UPDATE
        SET reason = EXCLUDED.reason,
            confidence = EXCLUDED.confidence
        """,
        (packet_id, event_id, clean_reason, clean_confidence),
    )

    # Keep the event span in sync with all packet assignments.
    if ts is not None:
        cursor.execute(
            """
            UPDATE event e
            SET start_timestamp = bounds.start_timestamp,
                end_timestamp = bounds.end_timestamp
            FROM (
                SELECT MIN(p.timestamp) AS start_timestamp,
                       MAX(p.timestamp) AS end_timestamp
                FROM packet_event pe
                JOIN packet p ON pe.packet_id = p.packet_id
                WHERE pe.event_id = %s
            ) bounds
            WHERE e.event_id = %s
            """,
            (event_id, event_id),
        )

    return "ok"


def update_event_description_record(cursor, event_id: int, description: str) -> str:
    """Update an event description when later packets clarify its purpose."""

    clean_description = " ".join(str(description or "").split())
    if not clean_description:
        return "description must not be empty"

    cursor.execute(
        """
        UPDATE event
        SET description = %s
        WHERE event_id = %s
        RETURNING event_id
        """,
        (clean_description, event_id),
    )
    row = cursor.fetchone()
    if not row:
        return f"event_id {event_id} not found"
    return "ok"


def ensure_packet_event_metadata_columns(cursor) -> None:
    """Verify reset/init migrations have created assignment metadata columns."""

    cursor.execute(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'packet_event'
          AND column_name IN ('reason', 'confidence')
        """
    )
    present = {
        row["column_name"] if isinstance(row, dict) else row[0]
        for row in cursor.fetchall() or []
    }
    missing = {"reason", "confidence"} - present
    if missing:
        missing_text = ", ".join(sorted(missing))
        raise RuntimeError(
            "packet_event is missing required column(s): "
            f"{missing_text}; run the database reset/admin migration"
        )


def packet_flow_tuple(cursor, packet_id: int) -> Optional[Dict[str, Any]]:
    """Return the packet's directional IP/port tuple and transport."""

    cursor.execute(
        """
        SELECT
            p.packet_id,
            p.recording_id,
            ip.src_addr,
            ip.dst_addr,
            CASE
                WHEN tcp.header_information_id IS NOT NULL THEN 'TCP'
                WHEN udp.header_information_id IS NOT NULL THEN 'UDP'
                ELSE 'unknown'
            END AS transport,
            COALESCE(tcp.src_port, udp.src_port) AS src_port,
            COALESCE(tcp.dst_port, udp.dst_port) AS dst_port
        FROM packet p
        LEFT JOIN LATERAL (
            SELECT ih.src_addr, ih.dst_addr
            FROM ip_header_information ih
            JOIN packet_header_information phi
              ON ih.header_information_id = phi.header_information_id
            WHERE phi.packet_id = p.packet_id
            ORDER BY ih.header_information_id ASC
            LIMIT 1
        ) ip ON TRUE
        LEFT JOIN LATERAL (
            SELECT th.header_information_id, th.src_port, th.dst_port
            FROM tcp_header_information th
            JOIN packet_header_information phi
              ON th.header_information_id = phi.header_information_id
            WHERE phi.packet_id = p.packet_id
            ORDER BY th.header_information_id ASC
            LIMIT 1
        ) tcp ON TRUE
        LEFT JOIN LATERAL (
            SELECT uh.header_information_id, uh.src_port, uh.dst_port
            FROM udp_header_information uh
            JOIN packet_header_information phi
              ON uh.header_information_id = phi.header_information_id
            WHERE phi.packet_id = p.packet_id
            ORDER BY uh.header_information_id ASC
            LIMIT 1
        ) udp ON TRUE
        WHERE p.packet_id = %s
        """,
        (packet_id,),
    )
    row = cursor.fetchone()
    return dict(row) if row else None


def event_packet_tuples(
    cursor,
    event_id: int,
    recording_id: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Return assigned packet tuples for one event."""

    params: List[Any] = [event_id]
    recording_clause = ""
    if recording_id is not None:
        recording_clause = "AND p.recording_id = %s"
        params.append(recording_id)

    cursor.execute(
        f"""
        SELECT p.packet_id, pe.reason, pe.confidence
        FROM packet_event pe
        JOIN packet p ON pe.packet_id = p.packet_id
        WHERE pe.event_id = %s
          {recording_clause}
        ORDER BY p.timestamp ASC NULLS LAST, p.number ASC, p.packet_id ASC
        """,
        tuple(params),
    )
    rows = cursor.fetchall() or []
    packets: List[Dict[str, Any]] = []
    for row in rows:
        packet_tuple = packet_flow_tuple(cursor, row["packet_id"])
        if packet_tuple:
            packet_tuple["reason"] = row.get("reason")
            packet_tuple["confidence"] = row.get("confidence")
            packets.append(packet_tuple)
    return packets


def event_tuple_mismatch(cursor, packet_id: int, event_id: int) -> Optional[str]:
    """Reject assignment when existing event packets use a different flow tuple."""

    target_tuple = packet_flow_tuple(cursor, packet_id)
    target_key = normalized_flow_key(target_tuple)
    if target_key is None:
        return f"packet_id {packet_id} has no matchable ip/port tuple"

    existing_packets = event_packet_tuples(cursor, event_id)
    existing_keys = {
        key
        for key in (normalized_flow_key(packet_tuple) for packet_tuple in existing_packets)
        if key is not None
    }
    if not existing_keys:
        return None
    if existing_keys == {target_key}:
        return None

    return (
        f"event_id {event_id} tuple mismatch for packet_id {packet_id}; "
        f"packet tuple is {format_normalized_flow_key(target_key)}"
    )


def normalized_flow_key(packet_tuple: Optional[Dict[str, Any]]) -> Optional[Tuple[str, str, str]]:
    """Normalize a directional packet tuple so request/response directions match."""

    if not packet_tuple:
        return None
    transport = str(packet_tuple.get("transport") or "unknown").upper()
    src_ip = packet_tuple.get("src_addr")
    dst_ip = packet_tuple.get("dst_addr")
    src_port = packet_tuple.get("src_port")
    dst_port = packet_tuple.get("dst_port")
    if (
        transport == "unknown"
        or src_ip is None
        or dst_ip is None
        or src_port is None
        or dst_port is None
    ):
        return None

    endpoints = sorted([f"{src_ip}:{src_port}", f"{dst_ip}:{dst_port}"])
    return (transport, endpoints[0], endpoints[1])


def normalize_reason(reason: str) -> str:
    """Keep stored LLM rationale concise and single-line."""

    return " ".join(str(reason or "").split())[:1000]


def normalize_confidence(confidence: Optional[float]) -> Optional[float]:
    """Clamp optional LLM confidence to the 0..1 range."""

    if confidence is None:
        return None
    try:
        value = float(confidence)
    except (TypeError, ValueError):
        return None
    return max(0.0, min(1.0, value))


def format_normalized_flow_key(key: Tuple[str, str, str]) -> str:
    """Render a normalized flow key for logs and MCP text output."""

    return f"{key[0]} {key[1]} <-> {key[2]}"


def format_packet_tuple(packet_tuple: Dict[str, Any]) -> str:
    """Render one packet's directional and normalized flow tuple."""

    key = normalized_flow_key(packet_tuple)
    normalized = format_normalized_flow_key(key) if key else "unmatchable"
    confidence = packet_tuple.get("confidence")
    confidence_text = (
        "unknown" if confidence is None else f"{float(confidence):.2f}"
    )
    reason = packet_tuple.get("reason") or ""
    return (
        f"packet_id:{packet_tuple['packet_id']} "
        f"{packet_tuple.get('src_addr')}:{packet_tuple.get('src_port')} -> "
        f"{packet_tuple.get('dst_addr')}:{packet_tuple.get('dst_port')} "
        f"{packet_tuple.get('transport')} "
        f"(flow:{normalized}, confidence:{confidence_text}, reason:{reason})"
    )
