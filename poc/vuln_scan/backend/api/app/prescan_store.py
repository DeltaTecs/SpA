from __future__ import annotations

import os
from contextlib import contextmanager
from dataclasses import asdict
from typing import Iterator, List, Optional

import psycopg2
from psycopg2.extras import RealDictCursor

from scanner_models import ScanSummary


CREATE_PRESCAN_TABLE = """
CREATE TABLE IF NOT EXISTS "PreScan" (
  event_id bigint PRIMARY KEY REFERENCES event(event_id) ON DELETE CASCADE,
  recording_id bigint REFERENCES recording(recording_id) ON DELETE SET NULL,
  most_interesting_packet_id bigint REFERENCES packet(packet_id) ON DELETE SET NULL,
  packet_content text NOT NULL DEFAULT '',
  event_summary text NOT NULL DEFAULT '',
  suspected_trigger text NOT NULL DEFAULT '',
  entrypoint_rationale text NOT NULL DEFAULT '',
  supporting_packet_ids bigint[] NOT NULL DEFAULT ARRAY[]::bigint[]
)
"""


@contextmanager
def _connection() -> Iterator:
    dsn = os.environ.get("DB_DSN")
    if dsn:
        conn = psycopg2.connect(dsn)
    else:
        conn = psycopg2.connect(
            host=os.environ.get("DB_HOST", "postgres"),
            port=int(os.environ.get("DB_PORT", "5432")),
            dbname=os.environ.get("DB_NAME", "main"),
            user=os.environ.get("DB_USER", "appuser"),
            password=os.environ.get("DB_PASSWORD", "appuser_password"),
        )
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def ensure_prescan_table() -> None:
    with _connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(CREATE_PRESCAN_TABLE)


def save_prescan(summary: ScanSummary) -> None:
    ensure_prescan_table()
    with _connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO "PreScan" (
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
    with _connection() as conn:
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
                FROM "PreScan"
                ORDER BY event_id
                """
            )
            return [dict(row) for row in cursor.fetchall()]


def get_prescan(event_id: int) -> Optional[ScanSummary]:
    ensure_prescan_table()
    with _connection() as conn:
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
                FROM "PreScan"
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
