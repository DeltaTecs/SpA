from __future__ import annotations

import sys
import unittest
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


API_DIR = Path(__file__).resolve().parents[1]
LLM_SRC_DIR = API_DIR.parent / "llm" / "src"
sys.path.insert(0, str(API_DIR))
sys.path.insert(0, str(LLM_SRC_DIR))

from app import scan_store  # noqa: E402
from analysis_types import phase_two_scan_type_rows  # noqa: E402


class _FakeCursor:
    def __init__(self) -> None:
        self.executed: list[tuple[str, tuple[Any, ...] | None]] = []
        self.fetchone_value: tuple[int, ...] | None = None
        self.fetchall_value: list[dict[str, Any]] = []

    def __enter__(self) -> "_FakeCursor":
        return self

    def __exit__(self, *args: Any) -> None:
        return None

    def execute(self, sql: str, params: tuple[Any, ...] | None = None) -> None:
        self.executed.append((sql, params))
        if "information_schema.tables" in sql:
            self.fetchall_value = [
                {"table_name": "scan_type"},
                {"table_name": "scans"},
            ]
        elif "SELECT scan_type_id" in sql:
            self.fetchone_value = (7,)
        elif "RETURNING scan_id" in sql:
            self.fetchone_value = (42,)
        elif "FROM scans" in sql:
            self.fetchall_value = [
                {
                    "scan_id": 42,
                    "scan_type_id": 7,
                    "scan_type_title": "Recon: Ports",
                    "scan_type_prompt": "Perform extensive port scans.",
                    "event_id": 13,
                    "llm_provider": "openai",
                    "llm_model": "gpt-4o-mini",
                    "user_constrains": "stay in scope",
                    "tools_used": "hexstrike__nmap_scan",
                    "summary": "## Report",
                }
            ]

    def executemany(self, sql: str, params: Any) -> None:
        self.executed.append((sql, tuple(params)))

    def fetchone(self) -> tuple[int, ...] | None:
        return self.fetchone_value

    def fetchall(self) -> list[dict[str, Any]]:
        return self.fetchall_value


class _FakeConnection:
    def __init__(self, cursor: _FakeCursor) -> None:
        self._cursor = cursor

    def cursor(self, *args: Any, **kwargs: Any) -> _FakeCursor:
        return self._cursor


@contextmanager
def _fake_connection(cursor: _FakeCursor) -> Iterator[_FakeConnection]:
    yield _FakeConnection(cursor)


class ScanStoreTest(unittest.TestCase):
    def test_ensure_scan_tables_seeds_static_phase_two_types(self) -> None:
        cursor = _FakeCursor()
        original_connection = scan_store.connection
        scan_store.connection = lambda: _fake_connection(cursor)
        try:
            scan_store.ensure_scan_tables()
        finally:
            scan_store.connection = original_connection

        seed_sql, seed_params = cursor.executed[-1]
        self.assertIn("INSERT INTO scan_type", seed_sql)
        self.assertEqual(seed_params, phase_two_scan_type_rows())

    def test_save_completed_phase_two_scan_inserts_requested_fields(self) -> None:
        cursor = _FakeCursor()
        original_connection = scan_store.connection
        original_ensure = scan_store.ensure_scan_tables
        scan_store.connection = lambda: _fake_connection(cursor)
        scan_store.ensure_scan_tables = lambda: None
        try:
            scan_id = scan_store.save_completed_phase_two_scan(
                scan_type_title="Recon: Ports",
                event_id=13,
                llm_provider="openai",
                llm_model="gpt-4o-mini",
                user_constraints="stay in scope",
                tools_used=["hexstrike__nmap_scan", "bash__bash"],
                summary="## Report",
            )
        finally:
            scan_store.connection = original_connection
            scan_store.ensure_scan_tables = original_ensure

        self.assertEqual(scan_id, 42)
        insert_sql, insert_params = cursor.executed[-1]
        self.assertIn("user_constrains", insert_sql)
        self.assertEqual(
            insert_params,
            (
                7,
                13,
                "openai",
                "gpt-4o-mini",
                "stay in scope",
                "hexstrike__nmap_scan, bash__bash",
                "## Report",
            ),
        )

    def test_list_phase_two_scans_returns_reports_for_event(self) -> None:
        cursor = _FakeCursor()
        original_connection = scan_store.connection
        original_ensure = scan_store.ensure_scan_tables
        scan_store.connection = lambda: _fake_connection(cursor)
        scan_store.ensure_scan_tables = lambda: None
        try:
            reports = scan_store.list_phase_two_scans(13)
        finally:
            scan_store.connection = original_connection
            scan_store.ensure_scan_tables = original_ensure

        select_sql, select_params = cursor.executed[-1]
        self.assertIn("JOIN scan_type", select_sql)
        self.assertEqual(select_params, (13,))
        self.assertEqual(reports[0]["scan_id"], 42)
        self.assertEqual(reports[0]["summary"], "## Report")


if __name__ == "__main__":
    unittest.main()
