"""Tests for the lenient vulnerability-checks output parser (no network)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.tasks.vulnerability_checks import parse_vulnerability_checks  # noqa: E402


class ParseVulnerabilityChecksTests(unittest.TestCase):
    def test_clean_json_array(self):
        raw = (
            '[{"title": "SQLi on login", "severity": "high", '
            '"references": ["CVE-1", "https://x"]}]'
        )
        result = parse_vulnerability_checks(raw)
        self.assertEqual(result.task_type, "vulnerability_checks")
        checks = result.payload["checks"]
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0]["title"], "SQLi on login")
        self.assertEqual(checks[0]["severity"], "high")
        self.assertEqual(checks[0]["references"], ["CVE-1", "https://x"])
        self.assertNotIn("parse_warning", result.payload)

    def test_fenced_json(self):
        raw = '```json\n[{"title": "Open redirect"}]\n```'
        checks = parse_vulnerability_checks(raw).payload["checks"]
        self.assertEqual(checks[0]["title"], "Open redirect")
        self.assertEqual(checks[0]["severity"], "info")  # default

    def test_object_with_checks_key(self):
        raw = '{"checks": [{"title": "XSS"}, {"title": "CSRF"}]}'
        checks = parse_vulnerability_checks(raw).payload["checks"]
        self.assertEqual([c["title"] for c in checks], ["XSS", "CSRF"])

    def test_array_embedded_in_prose(self):
        raw = 'Here are the checks:\n[{"title": "IDOR"}]\nThanks!'
        checks = parse_vulnerability_checks(raw).payload["checks"]
        self.assertEqual(checks[0]["title"], "IDOR")

    def test_invalid_severity_coerced(self):
        raw = '[{"title": "x", "severity": "SEVERE"}]'
        checks = parse_vulnerability_checks(raw).payload["checks"]
        self.assertEqual(checks[0]["severity"], "info")

    def test_references_as_string_wrapped(self):
        raw = '[{"title": "x", "references": "CVE-9"}]'
        checks = parse_vulnerability_checks(raw).payload["checks"]
        self.assertEqual(checks[0]["references"], ["CVE-9"])

    def test_technique_list_is_joined(self):
        raw = '[{"title": "x", "technique": ["Authentication bypass", "IDOR"]}]'
        checks = parse_vulnerability_checks(raw).payload["checks"]
        self.assertEqual(checks[0]["technique"], "Authentication bypass, IDOR")

    def test_garbage_falls_back_to_raw(self):
        result = parse_vulnerability_checks("not json at all")
        self.assertIn("parse_warning", result.payload)
        self.assertEqual(len(result.payload["checks"]), 1)
        self.assertIn("not json", result.payload["checks"][0]["description"])

    def test_empty_array_warns(self):
        result = parse_vulnerability_checks("[]")
        self.assertEqual(result.payload["checks"], [])
        self.assertIn("parse_warning", result.payload)


if __name__ == "__main__":
    unittest.main()
