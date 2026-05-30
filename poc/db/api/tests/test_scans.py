import unittest

from pydantic import ValidationError

from app.scans.repository import MAX_HISTORY_PER_TYPE
from app.scans.schemas import ScanResultCreate, ScanResultRecord, ScanResultSummary


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


if __name__ == "__main__":
    unittest.main()
