from __future__ import annotations

import sys
import unittest
from pathlib import Path


# cli_tools_catalog.py ships next to bash_mcp_server.py. It lives at the repo
# path when tests run from a checkout, and at /usr/local/bin inside the image.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, "/usr/local/bin")

import cli_tools_catalog  # noqa: E402


class CliToolsCatalogTest(unittest.TestCase):
    def test_catalogue_has_unique_binaries(self) -> None:
        names = [tool.binary for tool in cli_tools_catalog.CLI_TOOLS]
        self.assertEqual(len(names), len(set(names)))

    def test_find_cli_tool_resolves_known_and_unknown(self) -> None:
        self.assertIsNotNone(cli_tools_catalog.find_cli_tool("nmap"))
        self.assertIsNotNone(cli_tools_catalog.find_cli_tool("  nmap  "))
        self.assertIsNone(cli_tools_catalog.find_cli_tool("not-a-real-tool"))

    def test_http_tool_examples_set_a_custom_user_agent(self) -> None:
        # Every HTTP-facing example must demonstrate a custom User-Agent.
        for binary in ("httpx", "nuclei", "gobuster", "ffuf", "sqlmap", "nikto"):
            with self.subTest(binary=binary):
                tool = cli_tools_catalog.find_cli_tool(binary)
                self.assertIsNotNone(tool)
                self.assertIn(cli_tools_catalog.EXAMPLE_USER_AGENT, tool.example)

    def test_format_tool_example_mentions_user_agent_rate_and_detailed_hint(self) -> None:
        tool = cli_tools_catalog.find_cli_tool("nuclei")
        text = cli_tools_catalog.format_tool_example(tool, installed=True)

        self.assertIn("User-Agent", text)
        self.assertIn("rate limit", text)
        self.assertIn(tool.example, text)
        self.assertIn('cli_tool_usage("nuclei", detailed=true)', text)

    def test_format_tool_example_warns_when_not_installed(self) -> None:
        tool = cli_tools_catalog.find_cli_tool("nmap")
        text = cli_tools_catalog.format_tool_example(tool, installed=False)
        self.assertIn("not installed", text)

    def test_format_tool_help_wraps_help_output(self) -> None:
        tool = cli_tools_catalog.find_cli_tool("nmap")
        text = cli_tools_catalog.format_tool_help(
            tool, help_command="nmap -h", help_text="Usage: nmap ..."
        )
        self.assertIn("$ nmap -h", text)
        self.assertIn("Usage: nmap", text)
        self.assertIn("User-Agent", text)

    def test_cli_tool_list_header_explains_bash_mode_usage(self) -> None:
        # available_cli_tools() depends on what is installed, so only assert on
        # the static guidance the header always carries.
        text = cli_tools_catalog.format_cli_tool_list()
        self.assertIn("cli_tool_usage", text)
        self.assertIn("bash", text)


if __name__ == "__main__":
    unittest.main()
