from __future__ import annotations

from typing import Sequence

from psycopg2.extras import RealDictCursor

from analysis_types import phase_two_scan_type_rows

from .db import connection


REQUIRED_SCAN_TABLES = ("scan_type", "scans")


def ensure_scan_tables() -> None:
    with connection() as conn:
        with conn.cursor() as cursor:
            _assert_tables_exist(cursor, REQUIRED_SCAN_TABLES)
            _seed_scan_types(cursor)


def save_completed_phase_two_scan(
    *,
    scan_type_title: str,
    event_id: int,
    llm_provider: str,
    llm_model: str,
    user_constraints: str,
    tools_used: Sequence[str],
    summary: str,
) -> int:
    ensure_scan_tables()
    with connection() as conn:
        with conn.cursor() as cursor:
            scan_type_id = _scan_type_id(cursor, scan_type_title)
            cursor.execute(
                """
                INSERT INTO scans (
                  scan_type_id,
                  event_id,
                  llm_provider,
                  llm_model,
                  user_constrains,
                  tools_used,
                  summary
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING scan_id
                """,
                (
                    scan_type_id,
                    event_id,
                    llm_provider,
                    llm_model,
                    user_constraints,
                    ", ".join(tools_used),
                    summary,
                ),
            )
            row = cursor.fetchone()
    return int(row[0])


def list_phase_two_scans(event_id: int) -> list[dict]:
    ensure_scan_tables()
    with connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT
                  scans.scan_id,
                  scans.scan_type_id,
                  scan_type.title AS scan_type_title,
                  scan_type.prompt AS scan_type_prompt,
                  scans.event_id,
                  scans.llm_provider,
                  scans.llm_model,
                  scans.user_constrains,
                  scans.tools_used,
                  scans.summary
                FROM scans
                JOIN scan_type ON scan_type.scan_type_id = scans.scan_type_id
                WHERE scans.event_id = %s
                ORDER BY scans.scan_id DESC
                """,
                (event_id,),
            )
            return [dict(row) for row in cursor.fetchall()]


def get_phase_two_scans(scan_ids: Sequence[int]) -> list[dict]:
    unique_ids = sorted({int(scan_id) for scan_id in scan_ids})
    if not unique_ids:
        return []
    ensure_scan_tables()
    with connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT
                  scans.scan_id,
                  scans.scan_type_id,
                  scan_type.title AS scan_type_title,
                  scan_type.prompt AS scan_type_prompt,
                  scans.event_id,
                  scans.llm_provider,
                  scans.llm_model,
                  scans.user_constrains,
                  scans.tools_used,
                  scans.summary
                FROM scans
                JOIN scan_type ON scan_type.scan_type_id = scans.scan_type_id
                WHERE scans.scan_id = ANY(%s)
                ORDER BY scans.scan_id ASC
                """,
                (unique_ids,),
            )
            return [dict(row) for row in cursor.fetchall()]


def _seed_scan_types(cursor) -> None:
    cursor.executemany(
        """
        INSERT INTO scan_type (title, prompt)
        VALUES (%s, %s)
        ON CONFLICT (title) DO UPDATE SET
          prompt = EXCLUDED.prompt
        """,
        phase_two_scan_type_rows(),
    )


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


def _scan_type_id(cursor, title: str) -> int:
    cursor.execute(
        """
        SELECT scan_type_id
        FROM scan_type
        WHERE title = %s
        """,
        (title,),
    )
    row = cursor.fetchone()
    if row is not None:
        return int(row[0])

    cursor.execute(
        """
        INSERT INTO scan_type (title, prompt)
        VALUES (%s, '')
        RETURNING scan_type_id
        """,
        (title,),
    )
    return int(cursor.fetchone()[0])
