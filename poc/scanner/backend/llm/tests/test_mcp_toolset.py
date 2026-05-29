"""Tests for McpToolset.

The async connection helpers are replaced with stubs so no live MCP server (or
the ``mcp`` SDK) is required.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from llm.mcp import toolset as toolset_mod  # noqa: E402
from llm.mcp.toolset import McpToolset  # noqa: E402


class TestMcpToolset(unittest.TestCase):
    def setUp(self):
        self._orig_list = toolset_mod._list_tools_async
        self._orig_call = toolset_mod._call_tool_async
        self.call_args = []

    def tearDown(self):
        toolset_mod._list_tools_async = self._orig_list
        toolset_mod._call_tool_async = self._orig_call

    def _patch_list(self, payload):
        async def fake_list(url, transport):
            return payload

        toolset_mod._list_tools_async = fake_list

    def _patch_call(self, payload):
        async def fake_call(url, transport, name, arguments, timeout):
            self.call_args.append((name, arguments, timeout))
            return payload

        toolset_mod._call_tool_async = fake_call

    def test_rejects_unknown_transport(self):
        with self.assertRaises(ValueError):
            McpToolset("http://x/mcp", transport="carrier-pigeon")

    def test_name_defaults_to_host(self):
        toolset = McpToolset("http://mcp-packet-db:8765/mcp")
        self.assertEqual(toolset.name, "mcp-packet-db:8765")

    def test_list_tool_specs_conversion_and_cache(self):
        self._patch_list(
            {
                "tools": [
                    {
                        "name": "packet_info",
                        "description": "Get packet info",
                        "inputSchema": {"type": "object", "properties": {"packet_id": {"type": "integer"}}},
                    },
                    {"name": "no_schema"},  # missing description/schema -> defaults
                    {"description": "skipped, no name"},
                ]
            }
        )
        toolset = McpToolset("http://x/mcp")
        specs = toolset.list_tool_specs()

        self.assertEqual([s.name for s in specs], ["packet_info", "no_schema"])
        self.assertEqual(specs[0].parameters["properties"]["packet_id"]["type"], "integer")
        self.assertEqual(specs[1].description, "")
        self.assertEqual(specs[1].parameters, {"type": "object", "properties": {}})

        # Second call is served from cache (stub swapped out to prove it).
        toolset_mod._list_tools_async = None
        self.assertIs(toolset.list_tool_specs(), specs)

    def test_call_tool_flattens_text_content(self):
        self._patch_call(
            {"content": [{"type": "text", "text": "line1"}, {"type": "text", "text": "line2"}], "isError": False}
        )
        toolset = McpToolset("http://x/mcp", timeout=30.0)
        output = toolset.call_tool("packet_info", {"packet_id": 5})

        self.assertEqual(output, "line1\nline2")
        self.assertEqual(self.call_args, [("packet_info", {"packet_id": 5}, 30.0)])

    def test_call_tool_falls_back_to_json_when_no_text(self):
        self._patch_call({"content": [{"type": "image", "data": "..."}], "isError": False})
        toolset = McpToolset("http://x/mcp")
        output = toolset.call_tool("snapshot", {})
        self.assertIn("image", output)

    def test_call_tool_propagates_errors(self):
        async def boom(url, transport, name, arguments, timeout):
            raise RuntimeError("connection refused")

        toolset_mod._call_tool_async = boom
        toolset = McpToolset("http://x/mcp")
        with self.assertRaises(RuntimeError):
            toolset.call_tool("packet_info", {"packet_id": 1})


if __name__ == "__main__":
    unittest.main()
