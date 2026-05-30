"""Tests for terminating MCP tool processes (no network).

The toolset's MCP call and the HTTP bridge POST are stubbed so no live server
(or the ``mcp`` SDK) is required.
"""

from __future__ import annotations

import sys
import unittest
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import mcp_catalog  # noqa: E402
from app.config import Settings  # noqa: E402
from app.mcp_catalog import (  # noqa: E402
    StopSpec,
    _parse_jsonrpc_payload,
    build_catalog,
    terminate_tool_processes,
)


def _settings(**overrides) -> Settings:
    base = dict(
        mcp_packet_db_url="http://packet-db/mcp",
        tavily_url="http://tavily/mcp",
        hexstrike_bash_url="http://hexstrike:8766/mcp",
        hexstrike_tools_url="http://hexstrike:8767/mcp",
        openai_api_key=None,
        deepseek_api_key=None,
        max_concurrency=4,
        default_max_iterations=10,
        mcp_timeout=60.0,
        llm_timeout=120.0,
    )
    base.update(overrides)
    return Settings(**base)


class CatalogStopSpecTests(unittest.TestCase):
    def test_only_active_tooling_has_stop_specs(self):
        by_name = {e.name: e for e in build_catalog(_settings())}
        self.assertIsNone(by_name["packet-db"].stop)
        self.assertIsNone(by_name["tavily"].stop)
        self.assertEqual(by_name["hexstrike-bash"].stop, StopSpec("tool", "stop_active_bash"))
        self.assertEqual(by_name["hexstrike-tools"].stop, StopSpec("method", "tools/stop"))


class ParseJsonRpcPayloadTests(unittest.TestCase):
    def test_parses_sse(self):
        text = 'event: message\ndata: {"jsonrpc": "2.0", "result": {"message": "stopped 2"}}\n\n'
        self.assertEqual(_parse_jsonrpc_payload(text)["result"]["message"], "stopped 2")

    def test_parses_plain_json(self):
        self.assertEqual(_parse_jsonrpc_payload('{"result": {}}'), {"result": {}})


class TerminateToolProcessesTests(unittest.TestCase):
    def setUp(self):
        # The bash stop is a real MCP tool call; the bridge stop is a raw POST.
        self.tool_calls = []
        self.posts = []

        def fake_call_tool(self_toolset, name, arguments):
            self.tool_calls.append((self_toolset.name, name, arguments))
            return "Stop requested for 1 active Bash process(es)."

        self._orig_call_tool = mcp_catalog.McpToolset.call_tool
        mcp_catalog.McpToolset.call_tool = fake_call_tool

        def fake_post(url, method):
            self.posts.append((url, method))
            return "Stop requested for active HexStrike MCP subprocesses."

        self._orig_post = mcp_catalog._post_jsonrpc_method
        mcp_catalog._post_jsonrpc_method = fake_post

    def tearDown(self):
        mcp_catalog.McpToolset.call_tool = self._orig_call_tool
        mcp_catalog._post_jsonrpc_method = self._orig_post

    def test_stops_only_stop_capable_servers(self):
        results = terminate_tool_processes(_settings())
        by_name = {r.name: r for r in results}
        # Read-only servers (db, search) are skipped entirely.
        self.assertEqual(set(by_name), {"hexstrike-bash", "hexstrike-tools"})
        self.assertTrue(all(r.ok for r in results))
        # Bash via MCP tool call; bridge via raw JSON-RPC method.
        self.assertEqual(self.tool_calls, [("hexstrike-bash", "stop_active_bash", {})])
        self.assertEqual(self.posts, [("http://hexstrike:8767/mcp", "tools/stop")])

    def test_only_configured_servers_are_signalled(self):
        results = terminate_tool_processes(_settings(hexstrike_tools_url=None))
        self.assertEqual([r.name for r in results], ["hexstrike-bash"])
        self.assertEqual(self.posts, [])

    def test_failure_is_reported_not_raised(self):
        def boom(url, method):
            raise RuntimeError("bridge unreachable")

        mcp_catalog._post_jsonrpc_method = boom
        results = {r.name: r for r in terminate_tool_processes(_settings())}
        self.assertTrue(results["hexstrike-bash"].ok)  # the other server still stopped
        self.assertFalse(results["hexstrike-tools"].ok)
        self.assertIn("bridge unreachable", results["hexstrike-tools"].detail)


if __name__ == "__main__":
    unittest.main()
