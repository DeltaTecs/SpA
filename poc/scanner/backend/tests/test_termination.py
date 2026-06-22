"""Tests for terminating MCP tool processes (no network).

The toolset's MCP call and the HTTP bridge POST are stubbed so no live server
(or the ``mcp`` SDK) is required.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import mcp_catalog  # noqa: E402
from app.config import Settings  # noqa: E402
from app.mcp_catalog import (  # noqa: E402
    StopSpec,
    _post_admin_stop,
    build_catalog,
    terminate_tool_processes,
)


def _settings(**overrides) -> Settings:
    base = dict(
        mcp_packet_db_url="http://packet-db/mcp",
        db_api_url=None,
        tavily_url="http://tavily/mcp",
        hexstrike_bash_url="http://hexstrike:8766/mcp",
        hexstrike_tools_url="http://hexstrike:8767/mcp",
        hexstrike_tools_admin_token="test-admin-token",
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
        self.assertEqual(by_name["hexstrike-tools"].stop, StopSpec("admin", "/admin/tools/stop"))


class PostAdminStopTests(unittest.TestCase):
    def test_derives_admin_url_and_sends_bearer_token(self):
        response = mock.Mock()
        response.json.return_value = {"message": "stopped"}
        with mock.patch.object(mcp_catalog.httpx, "post", return_value=response) as post:
            self.assertEqual(
                _post_admin_stop(
                    "http://hexstrike:8767/mcp",
                    "/admin/tools/stop",
                    "secret",
                ),
                "stopped",
            )

        post.assert_called_once_with(
            "http://hexstrike:8767/admin/tools/stop",
            headers={
                "Accept": "application/json",
                "Authorization": "Bearer secret",
            },
            timeout=mcp_catalog.STOP_TIMEOUT_SECONDS,
        )
        response.raise_for_status.assert_called_once_with()


class TerminateToolProcessesTests(unittest.TestCase):
    def setUp(self):
        # The bash stop is a real MCP tool call; the bridge stop is an admin POST.
        self.tool_calls = []
        self.posts = []

        def fake_call_tool(self_toolset, name, arguments):
            self.tool_calls.append((self_toolset.name, name, arguments))
            return "Stop requested for 1 active Bash process(es)."

        self._orig_call_tool = mcp_catalog.McpToolset.call_tool
        mcp_catalog.McpToolset.call_tool = fake_call_tool

        def fake_post(url, path, token):
            self.posts.append((url, path, token))
            return "Stop requested for active HexStrike MCP subprocesses."

        self._orig_post = mcp_catalog._post_admin_stop
        mcp_catalog._post_admin_stop = fake_post

    def tearDown(self):
        mcp_catalog.McpToolset.call_tool = self._orig_call_tool
        mcp_catalog._post_admin_stop = self._orig_post

    def test_stops_only_stop_capable_servers(self):
        results = terminate_tool_processes(_settings())
        by_name = {r.name: r for r in results}
        # Read-only servers (db, search) are skipped entirely.
        self.assertEqual(set(by_name), {"hexstrike-bash", "hexstrike-tools"})
        self.assertTrue(all(r.ok for r in results))
        # Bash via MCP tool call; bridge via authenticated admin POST.
        self.assertEqual(self.tool_calls, [("hexstrike-bash", "stop_active_bash", {})])
        self.assertEqual(
            self.posts,
            [("http://hexstrike:8767/mcp", "/admin/tools/stop", "test-admin-token")],
        )

    def test_only_configured_servers_are_signalled(self):
        results = terminate_tool_processes(_settings(hexstrike_tools_url=None))
        self.assertEqual([r.name for r in results], ["hexstrike-bash"])
        self.assertEqual(self.posts, [])

    def test_failure_is_reported_not_raised(self):
        def boom(url, path, token):
            raise RuntimeError("bridge unreachable")

        mcp_catalog._post_admin_stop = boom
        results = {r.name: r for r in terminate_tool_processes(_settings())}
        self.assertTrue(results["hexstrike-bash"].ok)  # the other server still stopped
        self.assertFalse(results["hexstrike-tools"].ok)
        self.assertIn("bridge unreachable", results["hexstrike-tools"].detail)


if __name__ == "__main__":
    unittest.main()
