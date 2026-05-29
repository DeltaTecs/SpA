"""Tests for the vulnerability_checks task: prompts and toolset selection."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config import Settings  # noqa: E402
from app.schemas import Exchange, HttpExchangeInfo  # noqa: E402
from app.tasks.vulnerability_checks import VulnerabilityChecksTask  # noqa: E402


def _settings(*, tavily_url=None):
    return Settings(
        mcp_packet_db_url="http://mcp-packet-db:8765/mcp",
        tavily_url=tavily_url,
        openai_api_key=None,
        deepseek_api_key=None,
        max_concurrency=2,
        default_max_iterations=10,
        mcp_timeout=5.0,
        llm_timeout=5.0,
    )


class VulnerabilityChecksTaskTests(unittest.TestCase):
    def setUp(self):
        self.task = VulnerabilityChecksTask()

    def test_system_prompt_demands_json(self):
        self.assertIn("JSON", self.task.build_system_prompt())

    def test_prompt_parts_expose_system_and_user_sections(self):
        parts = self.task.prompt_parts()
        ids = [part.id for part in parts]
        self.assertIn("system_role", ids)
        self.assertIn("system_output_contract", ids)
        self.assertIn("user_preamble", ids)
        self.assertIn("user_instructions", ids)
        self.assertTrue(all(part.content for part in parts))

    def test_system_prompt_prioritizes_attack_angles(self):
        prompt = self.task.build_system_prompt()
        self.assertIn("Name the exploit technique", prompt)
        self.assertIn("attack angle", prompt)
        self.assertIn("Authentication or authorization bypass", prompt)
        self.assertIn("Code execution", prompt)
        self.assertIn("Injection paths", prompt)
        self.assertIn("do not reduce the plan to CVE enumeration", prompt)

    def test_user_prompt_includes_exchange_detail(self):
        exchange = Exchange(
            id="x",
            kind="http_pair",
            http=HttpExchangeInfo(method="GET", endpoint_path="/login", param_names=["user"]),
            representative_packet_ids=[1, 2],
        )
        prompt = self.task.build_user_prompt(exchange)
        self.assertIn("GET", prompt)
        self.assertIn("/login", prompt)
        self.assertIn("user", prompt)
        self.assertIn("1, 2", prompt)
        self.assertIn("name the exploit technique or attack angle", prompt)
        self.assertIn("CVE verification", prompt)

    def test_system_prompt_uses_overridden_section_text(self):
        prompt = self.task.build_system_prompt_for_run(
            {"system_role": "Custom role block for this analysis."}
        )
        self.assertIn("Custom role block for this analysis.", prompt)
        self.assertNotIn("authorized penetration-testing planner", prompt)
        self.assertIn("Output contract", prompt)

    def test_user_prompt_uses_overridden_text_around_exchange_detail(self):
        exchange = Exchange(id="x", kind="http_pair", http=HttpExchangeInfo(method="POST"))
        prompt = self.task.build_user_prompt_for_run(
            exchange,
            {
                "user_preamble": "Custom preamble.",
                "user_instructions": "Custom final instructions.",
            },
        )
        self.assertIn("Custom preamble.", prompt)
        self.assertIn("- kind: http_pair", prompt)
        self.assertIn("POST", prompt)
        self.assertIn("Custom final instructions.", prompt)
        self.assertNotIn("Inspect the referenced packets", prompt)

    def test_unknown_prompt_override_rejected(self):
        with self.assertRaises(ValueError):
            self.task.normalize_prompt_overrides({"does_not_exist": "x"})

    def test_toolsets_without_tavily(self):
        toolsets = self.task.select_toolsets(_settings())
        names = [t.name for t in toolsets]
        self.assertEqual(names, ["packet-db"])

    def test_toolsets_with_tavily(self):
        toolsets = self.task.select_toolsets(
            _settings(tavily_url="https://mcp.tavily.com/mcp/?tavilyApiKey=k")
        )
        names = [t.name for t in toolsets]
        self.assertEqual(names, ["packet-db", "tavily"])


if __name__ == "__main__":
    unittest.main()
