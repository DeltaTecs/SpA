import unittest
from unittest.mock import Mock, patch

from fastapi import HTTPException
from pydantic import ValidationError

from app.scans.repository import MAX_HISTORY_PER_TYPE, ScanRepository
from app.scans.router import delete_scan, get_scan_transcript, list_all_scans
from app.scans.schemas import (
    ScanResultCreate,
    ScanResultRecord,
    ScanResultSummary,
    TranscriptRecord,
)


class TestScanResultCreate(unittest.TestCase):
    def test_minimal_body_defaults(self):
        body = ScanResultCreate(scan_type="vulnerability_checks")
        self.assertIsNone(body.created_at)
        self.assertIsNone(body.provider)
        self.assertIsNone(body.model)
        self.assertEqual(body.payload, {})

    def test_scan_type_is_required(self):
        with self.assertRaises(ValidationError):
            ScanResultCreate(payload={"checks": []})

    def test_created_at_coerces_numeric_string(self):
        body = ScanResultCreate(scan_type="pentest", created_at="1717000000000")
        self.assertEqual(body.created_at, 1_717_000_000_000)

    def test_payload_is_preserved_verbatim(self):
        payload = {"status": "done", "tasks": [{"exchange_id": "a", "status": "done"}]}
        body = ScanResultCreate(scan_type="vulnerability_checks", payload=payload)
        self.assertEqual(body.payload, payload)

    def test_transcripts_default_empty_and_accept_items(self):
        self.assertEqual(ScanResultCreate(scan_type="pentest").transcripts, [])
        body = ScanResultCreate(
            scan_type="pentest",
            transcripts=[{"item_id": "i1", "steps": [{"kind": "reasoning", "text": "hi"}]}],
        )
        self.assertEqual(body.transcripts[0].item_id, "i1")
        self.assertEqual(body.transcripts[0].steps[0]["text"], "hi")


class TestScanResultRecord(unittest.TestCase):
    def test_record_includes_payload(self):
        record = ScanResultRecord(
            scan_result_id=1,
            recording_id=2,
            scan_type="pentest",
            created_at=123,
            provider="openai",
            model="gpt-x",
            payload={"k": "v"},
        )
        self.assertEqual(record.payload, {"k": "v"})
        self.assertEqual(record.created_at, 123)

    def test_summary_omits_payload_but_record_keeps_it(self):
        self.assertNotIn("payload", ScanResultSummary.model_fields)
        self.assertIn("payload", ScanResultRecord.model_fields)


class TestRetentionCap(unittest.TestCase):
    def test_history_cap_is_a_positive_int(self):
        self.assertIsInstance(MAX_HISTORY_PER_TYPE, int)
        self.assertGreater(MAX_HISTORY_PER_TYPE, 0)


class TestScanRepositoryDelete(unittest.TestCase):
    @patch("app.scans.repository.dict_cursor")
    def test_delete_returns_whether_a_row_existed(self, dict_cursor):
        cursor = Mock(rowcount=1)
        dict_cursor.return_value.__enter__.return_value = cursor

        self.assertTrue(ScanRepository().delete(7))
        cursor.execute.assert_called_once_with(
            "DELETE FROM scan_result WHERE scan_result_id = %s",
            (7,),
        )

    @patch("app.scans.repository.dict_cursor")
    def test_delete_returns_false_for_unknown_scan(self, dict_cursor):
        cursor = Mock(rowcount=0)
        dict_cursor.return_value.__enter__.return_value = cursor

        self.assertFalse(ScanRepository().delete(7))


class TestScanRepositoryCreateAndTranscript(unittest.TestCase):
    @staticmethod
    def _record_row():
        return {
            "scan_result_id": 42,
            "recording_id": 2,
            "scan_type": "pentest",
            "created_at": 123,
            "provider": None,
            "model": None,
            "payload": {"items": []},
        }

    @patch("app.scans.repository.dict_cursor")
    def test_create_inserts_transcripts_linked_to_new_scan(self, dict_cursor):
        cursor = Mock()
        cursor.fetchone.return_value = self._record_row()
        dict_cursor.return_value.__enter__.return_value = cursor

        body = ScanResultCreate(
            scan_type="pentest",
            created_at=123,
            payload={"items": []},
            transcripts=[{"item_id": "i1", "steps": [{"kind": "tool_call"}]}],
        )
        record = ScanRepository().create(2, body)

        self.assertEqual(record.scan_result_id, 42)
        inserts = [
            call
            for call in cursor.execute.call_args_list
            if "INSERT INTO scan_transcript" in call.args[0]
        ]
        self.assertEqual(len(inserts), 1)
        params = inserts[0].args[1]
        self.assertEqual(params[0], 42)  # references the just-created scan_result
        self.assertEqual(params[1], "i1")
        self.assertEqual(params[2].adapted, [{"kind": "tool_call"}])  # Json-wrapped steps

    @patch("app.scans.repository.dict_cursor")
    def test_create_without_transcripts_inserts_none(self, dict_cursor):
        cursor = Mock()
        cursor.fetchone.return_value = self._record_row()
        dict_cursor.return_value.__enter__.return_value = cursor

        ScanRepository().create(2, ScanResultCreate(scan_type="pentest", payload={"items": []}))

        self.assertFalse(
            any("scan_transcript" in call.args[0] for call in cursor.execute.call_args_list)
        )

    @patch("app.scans.repository.dict_cursor")
    def test_get_transcript_returns_record(self, dict_cursor):
        cursor = Mock()
        cursor.fetchone.return_value = {
            "item_id": "i1",
            "steps": [{"kind": "reasoning", "text": "hi"}],
        }
        dict_cursor.return_value.__enter__.return_value = cursor

        record = ScanRepository().get_transcript(42, "i1")

        self.assertIsInstance(record, TranscriptRecord)
        self.assertEqual(record.item_id, "i1")
        self.assertEqual(record.steps[0]["text"], "hi")
        _, params = cursor.execute.call_args.args
        self.assertEqual(params, (42, "i1"))

    @patch("app.scans.repository.dict_cursor")
    def test_get_transcript_none_when_absent(self, dict_cursor):
        cursor = Mock()
        cursor.fetchone.return_value = None
        dict_cursor.return_value.__enter__.return_value = cursor

        self.assertIsNone(ScanRepository().get_transcript(42, "missing"))


class TestGetScanTranscriptRoute(unittest.TestCase):
    @patch("app.scans.router.repository.get_transcript")
    def test_returns_transcript(self, get_transcript):
        get_transcript.return_value = TranscriptRecord(item_id="i1", steps=[])
        result = get_scan_transcript(42, item_id="i1")
        self.assertEqual(result.item_id, "i1")
        get_transcript.assert_called_once_with(42, "i1")

    @patch("app.scans.router.repository.get_transcript", return_value=None)
    def test_404_when_transcript_absent(self, _get_transcript):
        with self.assertRaises(HTTPException) as ctx:
            get_scan_transcript(42, item_id="i1")
        self.assertEqual(ctx.exception.status_code, 404)


class TestScanRepositoryListAll(unittest.TestCase):
    @staticmethod
    def _summary_row():
        return {
            "scan_result_id": 1,
            "recording_id": 2,
            "scan_type": "pentest",
            "created_at": 123,
            "provider": None,
            "model": None,
        }

    @patch("app.scans.repository.dict_cursor")
    def test_no_filters_omits_where_clause(self, dict_cursor):
        cursor = Mock()
        cursor.fetchall.return_value = [self._summary_row()]
        dict_cursor.return_value.__enter__.return_value = cursor

        rows = ScanRepository().list_all()

        self.assertEqual(len(rows), 1)
        self.assertIsInstance(rows[0], ScanResultSummary)
        sql, params = cursor.execute.call_args.args
        self.assertNotIn("WHERE", sql)
        self.assertEqual(params, ())

    @patch("app.scans.repository.dict_cursor")
    def test_scan_type_only_filters_on_type_across_recordings(self, dict_cursor):
        cursor = Mock()
        cursor.fetchall.return_value = []
        dict_cursor.return_value.__enter__.return_value = cursor

        ScanRepository().list_all(scan_type="exploit")

        sql, params = cursor.execute.call_args.args
        self.assertIn("scan_type = %s", sql)
        self.assertNotIn("recording_id = %s", sql)
        self.assertEqual(params, ("exploit",))

    @patch("app.scans.repository.dict_cursor")
    def test_both_filters_combined(self, dict_cursor):
        cursor = Mock()
        cursor.fetchall.return_value = []
        dict_cursor.return_value.__enter__.return_value = cursor

        ScanRepository().list_all(scan_type="pentest", recording_id=5)

        sql, params = cursor.execute.call_args.args
        self.assertIn("recording_id = %s AND scan_type = %s", sql)
        self.assertEqual(params, (5, "pentest"))

    @patch("app.scans.repository.dict_cursor")
    def test_list_delegates_to_list_all(self, dict_cursor):
        cursor = Mock()
        cursor.fetchall.return_value = []
        dict_cursor.return_value.__enter__.return_value = cursor

        ScanRepository().list(9, "pentest")

        _, params = cursor.execute.call_args.args
        self.assertEqual(params, (9, "pentest"))


class TestListAllScansRoute(unittest.TestCase):
    @patch("app.scans.router.repository.list_all", return_value=[])
    def test_route_forwards_both_filters(self, list_all):
        self.assertEqual(list_all_scans(scan_type="exploit", recording_id=3), [])
        list_all.assert_called_once_with(scan_type="exploit", recording_id=3)

    @patch("app.scans.router.repository.list_all", return_value=[])
    def test_route_forwards_none_filters(self, list_all):
        # Explicit Nones (FastAPI supplies these when the query params are absent).
        list_all_scans(scan_type=None, recording_id=None)
        list_all.assert_called_once_with(scan_type=None, recording_id=None)


class TestDeleteScanRoute(unittest.TestCase):
    @patch("app.scans.router.repository.delete", return_value=True)
    def test_delete_returns_acknowledgement(self, delete):
        self.assertEqual(delete_scan(7), {"deleted": True})
        delete.assert_called_once_with(7)

    @patch("app.scans.router.repository.delete", return_value=False)
    def test_delete_returns_404_for_unknown_scan(self, delete):
        with self.assertRaises(HTTPException) as ctx:
            delete_scan(7)

        self.assertEqual(ctx.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
