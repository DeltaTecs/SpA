from __future__ import annotations

from typing import List


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


def events_for_recording_text(cursor, recording_id: int) -> str:
    """Return persisted events that already have packets in this recording."""
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

    lines: List[str] = []
    for row in rows:
        lines.append(
            f"event_id:{row['event_id']}  description:{row['description']}  "
            f"start:{row['start_timestamp']}  end:{row['end_timestamp']}"
        )
    return "\n".join(lines)


def create_event_record(cursor, description: str) -> str:
    """Create an event without assigning packets."""
    cursor.execute(
        """
        INSERT INTO event (description, start_timestamp, end_timestamp)
        VALUES (%s, 9223372036854775807, -9223372036854775808)
        RETURNING event_id
        """,
        (description,),
    )
    event_id = cursor.fetchone()[0]
    return f"event_id:{event_id}"


def create_event_and_assign_packet_record(cursor, packet_id: int, description: str) -> str:
    """Atomically create an event and assign one packet to avoid orphans."""
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
            INSERT INTO packet_event (packet_id, event_id)
            SELECT pkt.packet_id, new_event.event_id
            FROM pkt
            CROSS JOIN new_event
            RETURNING event_id
        )
        SELECT event_id
        FROM assignment
        """,
        (packet_id, description),
    )
    row = cursor.fetchone()
    if not row:
        return f"packet_id {packet_id} not found"

    if isinstance(row, dict):
        event_id = row["event_id"]
    else:
        event_id = row[0]
    return f"event_id:{event_id}"


def assign_packet_to_event_record(cursor, packet_id: int, event_id: int) -> str:
    """Assign an existing packet to an existing event and update event bounds."""
    cursor.execute(
        "SELECT timestamp FROM packet WHERE packet_id = %s",
        (packet_id,),
    )
    pkt = cursor.fetchone()
    if not pkt:
        return f"packet_id {packet_id} not found"

    ts = pkt["timestamp"]

    cursor.execute(
        """
        INSERT INTO packet_event (packet_id, event_id)
        VALUES (%s, %s)
        ON CONFLICT (packet_id, event_id) DO NOTHING
        """,
        (packet_id, event_id),
    )

    # Keep the event span in sync with all packet assignments.
    if ts is not None:
        cursor.execute(
            """
            UPDATE event
            SET start_timestamp = LEAST(COALESCE(start_timestamp, %s), %s),
                end_timestamp   = GREATEST(COALESCE(end_timestamp, %s), %s)
            WHERE event_id = %s
            """,
            (ts, ts, ts, ts, event_id),
        )

    return "ok"
