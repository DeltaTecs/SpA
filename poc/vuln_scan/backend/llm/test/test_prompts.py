from __future__ import annotations

import sys
import unittest
from pathlib import Path


SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

from prompts import build_prior_reports_compaction_system_prompt  # noqa: E402


class PromptTest(unittest.TestCase):
    def test_prior_report_compaction_prompt_preserves_technical_findings(self) -> None:
        prompt = build_prior_reports_compaction_system_prompt()

        self.assertIn("short Markdown report", prompt)
        self.assertIn("Do not over-condense", prompt)
        self.assertIn("hosts, domains, IPs, ports", prompt)
        self.assertIn("Do not invent facts", prompt)
        self.assertIn("Return Markdown only", prompt)


if __name__ == "__main__":
    unittest.main()
