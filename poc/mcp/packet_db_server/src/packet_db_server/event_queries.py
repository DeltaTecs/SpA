from __future__ import annotations

from typing import List


def events_for_recording_text(cursor, recording_id: int) -> str:
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
    cursor.execute(
        """
        INSERT INTO event (description)
        VALUES (%s)
        RETURNING event_id
        """,
        (description,),
    )
    event_id = cursor.fetchone()[0]
    return f"event_id:{event_id}"


def assign_packet_to_event_record(cursor, packet_id: int, event_id: int) -> str:
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
