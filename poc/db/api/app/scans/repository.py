from __future__ import annotations

import logging
import time
from typing import Any, List, Optional

from psycopg2.extras import Json

from ..db import dict_cursor
from .schemas import ScanResultCreate, ScanResultRecord, ScanResultSummary

logger = logging.getLogger(__name__)

#: Keep at most this many stored scans per ``(recording_id, scan_type)``; older
#: ones are pruned on insert so history stays bounded.
MAX_HISTORY_PER_TYPE = 50

_SUMMARY_COLUMNS = "scan_result_id, recording_id, scan_type, created_at, provider, model"
_RECORD_COLUMNS = _SUMMARY_COLUMNS + ", payload"


class ScanRepository:
    """Persists and retrieves scan-result snapshots."""

    def create(self, recording_id: int, body: ScanResultCreate) -> ScanResultRecord:
        """Insert a snapshot and prune history beyond the cap, in one transaction."""
        created_at = body.created_at if body.created_at is not None else int(time.time() * 1000)
        with dict_cursor() as cursor:
            cursor.execute(
                f"""
                INSERT INTO scan_result
                    (recording_id, scan_type, created_at, provider, model, payload)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING {_RECORD_COLUMNS}
                """,
                (recording_id, body.scan_type, created_at, body.provider, body.model, Json(body.payload)),
            )
            row = cursor.fetchone()
            self._prune(cursor, recording_id, body.scan_type)
        return ScanResultRecord(**row)

    def _prune(self, cursor: Any, recording_id: int, scan_type: str) -> None:
        """Delete all but the newest ``MAX_HISTORY_PER_TYPE`` rows for this key."""
        cursor.execute(
            """
            DELETE FROM scan_result
            WHERE recording_id = %s AND scan_type = %s
              AND scan_result_id NOT IN (
                SELECT scan_result_id FROM scan_result
                WHERE recording_id = %s AND scan_type = %s
                ORDER BY created_at DESC, scan_result_id DESC
                LIMIT %s
              )
            """,
            (recording_id, scan_type, recording_id, scan_type, MAX_HISTORY_PER_TYPE),
        )

    def latest(self, recording_id: int, scan_type: str) -> Optional[ScanResultRecord]:
        """Return the most recent stored scan of a type, or ``None``."""
        with dict_cursor() as cursor:
            cursor.execute(
                f"""
                SELECT {_RECORD_COLUMNS} FROM scan_result
                WHERE recording_id = %s AND scan_type = %s
                ORDER BY created_at DESC, scan_result_id DESC
                LIMIT 1
                """,
                (recording_id, scan_type),
            )
            row = cursor.fetchone()
        return ScanResultRecord(**row) if row else None

    def list(self, recording_id: int, scan_type: Optional[str] = None) -> List[ScanResultSummary]:
        """List stored scans (metadata only) for a recording, newest first."""
        return self.list_all(scan_type=scan_type, recording_id=recording_id)

    def list_all(
        self, scan_type: Optional[str] = None, recording_id: Optional[int] = None
    ) -> List[ScanResultSummary]:
        """List stored scans (metadata only) across recordings, newest first.

        Both filters are optional: omit ``recording_id`` to list a scan type
        across every recording (used by the queue's Saved reports browser).
        """
        clauses: List[str] = []
        params: List[Any] = []
        if recording_id is not None:
            clauses.append("recording_id = %s")
            params.append(recording_id)
        if scan_type is not None:
            clauses.append("scan_type = %s")
            params.append(scan_type)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with dict_cursor() as cursor:
            cursor.execute(
                f"""
                SELECT {_SUMMARY_COLUMNS} FROM scan_result
                {where}
                ORDER BY created_at DESC, scan_result_id DESC
                """,
                tuple(params),
            )
            rows = cursor.fetchall() or []
        return [ScanResultSummary(**row) for row in rows]

    def get(self, scan_result_id: int) -> Optional[ScanResultRecord]:
        """Return a single stored scan including its payload, or ``None``."""
        with dict_cursor() as cursor:
            cursor.execute(
                f"SELECT {_RECORD_COLUMNS} FROM scan_result WHERE scan_result_id = %s",
                (scan_result_id,),
            )
            row = cursor.fetchone()
        return ScanResultRecord(**row) if row else None

    def delete(self, scan_result_id: int) -> bool:
        """Delete one stored scan snapshot, returning whether it existed."""
        with dict_cursor() as cursor:
            cursor.execute(
                "DELETE FROM scan_result WHERE scan_result_id = %s",
                (scan_result_id,),
            )
            return cursor.rowcount > 0
