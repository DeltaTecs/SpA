from __future__ import annotations

import sys
import unittest
from pathlib import Path


SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

from prompts import (  # noqa: E402
    build_phase_two_system_prompt,
    build_prior_report_compaction_system_prompt,
    build_prior_reports_compaction_system_prompt,
    build_smart_approval_system_prompt,
)


class PromptTest(unittest.TestCase):
    def test_phase_two_prompt_lists_hexstrike_wordlists(self) -> None:
        prompt = build_phase_two_system_prompt(
            analysis_types=["Recon: HTTP Path/API"],
            has_app_details=False,
            has_user_actions=False,
            has_prescan=True,
        )

        self.assertIn("Wordlists available in the HexStrike container", prompt)
        self.assertIn(
            "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
            prompt,
        )
        self.assertIn(
            "/usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt",
            prompt,
        )
        self.assertIn(
            "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
            prompt,
        )
        self.assertIn(
            "/usr/share/wordlists/assetnote/httparchive_directories_1m.txt",
            prompt,
        )
        self.assertIn(
            "/usr/share/wordlists/assetnote/httparchive_apiroutes.txt",
            prompt,
        )
        self.assertIn(
            "/usr/share/wordlists/assetnote/httparchive_parameters_top_1m.txt",
            prompt,
        )

    def test_phase_two_prompt_bash_mode_describes_cli_helper_tools(self) -> None:
        prompt = build_phase_two_system_prompt(
            analysis_types=["Recon: HTTP Path/API"],
            has_app_details=False,
            has_user_actions=False,
            has_prescan=True,
            bash_mode=True,
        )

        self.assertIn("Bash mode is enabled", prompt)
        self.assertIn("list_cli_tools", prompt)
        self.assertIn("cli_tool_usage", prompt)
        # HexStrike MCP scanning tools are not offered in bash mode.
        self.assertNotIn("HexStrike MCP tools, and a Bash MCP server", prompt)

    def test_phase_two_prompt_without_bash_mode_offers_hexstrike_tools(self) -> None:
        prompt = build_phase_two_system_prompt(
            analysis_types=["Recon: HTTP Path/API"],
            has_app_details=False,
            has_user_actions=False,
            has_prescan=True,
        )

        self.assertIn("HexStrike MCP tools", prompt)
        self.assertNotIn("Bash mode is enabled", prompt)
        self.assertNotIn("list_cli_tools", prompt)

    def test_prior_report_compaction_prompt_preserves_technical_findings(self) -> None:
        prompt = build_prior_report_compaction_system_prompt()

        self.assertIn("short Markdown report", prompt)
        self.assertIn("Do not over-condense", prompt)
        self.assertIn("hosts, domains, IPs, ports", prompt)
        self.assertIn("Do not invent facts", prompt)
        self.assertIn("Return Markdown only", prompt)

    def test_plural_prior_report_compaction_prompt_name_is_compatible(self) -> None:
        self.assertEqual(
            build_prior_reports_compaction_system_prompt(),
            build_prior_report_compaction_system_prompt(),
        )

    def test_smart_approval_prompt_covers_all_review_criteria(self) -> None:
        prompt = build_smart_approval_system_prompt()

        # The reviewer must check user constraints, local safety, and that
        # remote testing stays proportionate to proving a vulnerability.
        self.assertIn("user constraint", prompt.lower())
        self.assertIn("local machine", prompt.lower())
        self.assertIn("PROVE", prompt)
        self.assertIn("exploitation", prompt.lower())
        # Rejection must be the conservative default.
        self.assertIn("do NOT approve", prompt)
        # The decision must be returned as a JSON object.
        self.assertIn('"approved"', prompt)
        self.assertIn('"reasoning"', prompt)


if __name__ == "__main__":
    unittest.main()
