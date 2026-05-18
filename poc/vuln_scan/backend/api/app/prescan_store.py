from __future__ import annotations

from dataclasses import asdict
from typing import List, Optional, Sequence

from psycopg2.extras import RealDictCursor

from scanner_models import ScanSummary

from .db import connection


REQUIRED_PRESCAN_TABLES = ("pre_scan",)


def ensure_prescan_table() -> None:
    with connection() as conn:
        with conn.cursor() as cursor:
            _assert_tables_exist(cursor, REQUIRED_PRESCAN_TABLES)


def save_prescan(summary: ScanSummary) -> None:
    ensure_prescan_table()
    with connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO pre_scan (
                  event_id,
                  recording_id,
                  most_interesting_packet_id,
                  packet_content,
                  event_summary,
                  suspected_trigger,
                  entrypoint_rationale,
                  supporting_packet_ids
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (event_id) DO UPDATE SET
                  recording_id = EXCLUDED.recording_id,
                  most_interesting_packet_id = EXCLUDED.most_interesting_packet_id,
                  packet_content = EXCLUDED.packet_content,
                  event_summary = EXCLUDED.event_summary,
                  suspected_trigger = EXCLUDED.suspected_trigger,
                  entrypoint_rationale = EXCLUDED.entrypoint_rationale,
                  supporting_packet_ids = EXCLUDED.supporting_packet_ids
                """,
                (
                    summary.event_id,
                    summary.recording_id,
                    summary.most_interesting_packet_id,
                    summary.packet_content,
                    summary.event_summary,
                    summary.suspected_trigger,
                    summary.entrypoint_rationale,
                    summary.supporting_packet_ids,
                ),
            )


def list_prescans() -> List[dict]:
    ensure_prescan_table()
    with connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT
                  event_id,
                  recording_id,
                  most_interesting_packet_id,
                  packet_content,
                  event_summary,
                  suspected_trigger,
                  entrypoint_rationale,
                  supporting_packet_ids
                FROM pre_scan
                ORDER BY event_id
                """
            )
            return [dict(row) for row in cursor.fetchall()]


def get_prescan(event_id: int) -> Optional[ScanSummary]:
    ensure_prescan_table()
    with connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT
                  event_id,
                  recording_id,
                  most_interesting_packet_id,
                  packet_content,
                  event_summary,
                  suspected_trigger,
                  entrypoint_rationale,
                  supporting_packet_ids
                FROM pre_scan
                WHERE event_id = %s
                """,
                (event_id,),
            )
            row = cursor.fetchone()
    if row is None:
        return None
    return ScanSummary.from_dict(dict(row), event_id=event_id, recording_id=row["recording_id"])


def prescan_dict(summary: ScanSummary) -> dict:
    return asdict(summary)


def _assert_tables_exist(cursor, table_names: Sequence[str]) -> None:
    cursor.execute(
        """
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_name = ANY(%s)
        """,
        (list(table_names),),
    )
    present = {
        row["table_name"] if isinstance(row, dict) else row[0]
        for row in cursor.fetchall() or []
    }
    missing = set(table_names) - present
    if missing:
        missing_text = ", ".join(sorted(missing))
        raise RuntimeError(
            "Database schema is missing required table(s): "
            f"{missing_text}; run the database reset/admin migration"
        )
