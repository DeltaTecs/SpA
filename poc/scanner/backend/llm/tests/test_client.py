"""Tests for the McpLlmClient orchestration loop, using fakes (no network/MCP)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from llm.client import McpLlmClient, ToolDecision  # noqa: E402
from llm.provider.base import BaseProvider, ChatResult, ToolCall, ToolSpec  # noqa: E402


class ScriptedProvider(BaseProvider):
    """Provider that returns a pre-scripted sequence of ChatResults."""

    name = "scripted"

    def __init__(self, responses):
        super().__init__(api_key=None, model="test")
        self._responses = list(responses)
        self.received = []  # (messages, tools) per chat() call

    def chat(self, messages, tools=None):
        self.received.append((list(messages), tools))
        if self._responses:
            return self._responses.pop(0)
        # Default to a terminal answer if the script runs out.
        return ChatResult(content="(no more scripted responses)")


class FakeToolset:
    def __init__(self, specs, *, name="fake", outputs=None, raises=False):
        self.name = name
        self._specs = specs
        self._outputs = outputs or {}
        self._raises = raises
        self.calls = []

    def list_tool_specs(self):
        return self._specs

    def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        if self._raises:
            raise RuntimeError("tool exploded")
        return self._outputs.get(name, "tool-output")


def _spec(name):
    return ToolSpec(name=name, description=f"desc {name}", parameters={"type": "object"})


class TestMcpLlmClient(unittest.TestCase):
    def test_returns_answer_without_tools(self):
        provider = ScriptedProvider([ChatResult(content="just an answer")])
        client = McpLlmClient(provider, [])
        result = client.run("hello")

        self.assertEqual(result.output, "just an answer")
        self.assertEqual(result.iterations, 1)
        self.assertFalse(result.stopped_on_limit)

    def test_executes_tool_call_then_answers(self):
        provider = ScriptedProvider(
            [
                ChatResult(
                    content=None,
                    reasoning_content="need lookup",
                    tool_calls=[ToolCall(id="c1", name="lookup", arguments={"q": "x"})],
                ),
                ChatResult(content="final answer"),
            ]
        )
        toolset = FakeToolset([_spec("lookup")], outputs={"lookup": "looked-up"})
        client = McpLlmClient(provider, [toolset])
        result = client.run("question", system="be brief")

        self.assertEqual(result.output, "final answer")
        self.assertEqual(result.iterations, 2)
        self.assertEqual(toolset.calls, [("lookup", {"q": "x"})])
        self.assertEqual([c.name for c in result.tool_calls], ["lookup"])

        # The tools list was forwarded; the system message seeded the transcript.
        first_messages, first_tools = provider.received[0]
        self.assertEqual([t.name for t in first_tools], ["lookup"])
        self.assertEqual(first_messages[0].role, "system")
        # On the second turn the tool result was fed back to the model.
        second_messages, _ = provider.received[1]
        self.assertTrue(any(m.role == "tool" and m.content == "looked-up" for m in second_messages))
        self.assertTrue(
            any(
                m.role == "assistant" and m.reasoning_content == "need lookup"
                for m in second_messages
            )
        )

    def test_unknown_tool_reported_back(self):
        provider = ScriptedProvider(
            [
                ChatResult(tool_calls=[ToolCall(id="c1", name="ghost", arguments={})]),
                ChatResult(content="recovered"),
            ]
        )
        toolset = FakeToolset([_spec("lookup")])
        client = McpLlmClient(provider, [toolset])
        result = client.run("q")

        self.assertEqual(result.output, "recovered")
        # The model's ghost call never reached the (unrelated) toolset.
        self.assertEqual(toolset.calls, [])
        second_messages, _ = provider.received[1]
        self.assertTrue(any("unknown tool" in (m.content or "") for m in second_messages))

    def test_tool_exception_reported_back(self):
        provider = ScriptedProvider(
            [
                ChatResult(tool_calls=[ToolCall(id="c1", name="lookup", arguments={})]),
                ChatResult(content="handled"),
            ]
        )
        toolset = FakeToolset([_spec("lookup")], raises=True)
        client = McpLlmClient(provider, [toolset])
        result = client.run("q")

        self.assertEqual(result.output, "handled")
        second_messages, _ = provider.received[1]
        self.assertTrue(any("Error executing tool" in (m.content or "") for m in second_messages))

    def test_duplicate_tool_names_first_wins(self):
        provider = ScriptedProvider([ChatResult(content="ok")])
        ts_a = FakeToolset([_spec("dup")], name="A")
        ts_b = FakeToolset([_spec("dup"), _spec("unique")], name="B")
        client = McpLlmClient(provider, [ts_a, ts_b])
        client.run("q")

        _, tools = provider.received[0]
        names = [t.name for t in tools]
        self.assertEqual(names.count("dup"), 1)
        self.assertIn("unique", names)

    def test_allowed_tools_filters_specs(self):
        provider = ScriptedProvider([ChatResult(content="ok")])
        toolset = FakeToolset([_spec("keep"), _spec("hide")])
        client = McpLlmClient(provider, [toolset], allowed_tools={"keep"})
        client.run("q")

        _, tools = provider.received[0]
        self.assertEqual([t.name for t in tools], ["keep"])

    def test_approver_denial_skips_execution_and_feeds_back(self):
        provider = ScriptedProvider(
            [
                ChatResult(tool_calls=[ToolCall(id="c1", name="lookup", arguments={"q": "x"})]),
                ChatResult(content="adjusted"),
            ]
        )
        toolset = FakeToolset([_spec("lookup")], outputs={"lookup": "secret"})

        class DenyApprover:
            def review(self, call):
                return ToolDecision(False, "out of scope")

        client = McpLlmClient(provider, [toolset], approver=DenyApprover())
        result = client.run("q")

        self.assertEqual(result.output, "adjusted")
        self.assertEqual(toolset.calls, [])  # never executed
        second_messages, _ = provider.received[1]
        denial = next(m for m in second_messages if m.role == "tool")
        self.assertIn("DENIED by reviewer: out of scope", denial.content)

    def test_approver_approval_executes(self):
        provider = ScriptedProvider(
            [
                ChatResult(tool_calls=[ToolCall(id="c1", name="lookup", arguments={})]),
                ChatResult(content="done"),
            ]
        )
        toolset = FakeToolset([_spec("lookup")], outputs={"lookup": "value"})

        class AllowApprover:
            def review(self, call):
                return ToolDecision(True)

        client = McpLlmClient(provider, [toolset], approver=AllowApprover())
        client.run("q")
        self.assertEqual(toolset.calls, [("lookup", {})])

    def test_stops_on_max_iterations(self):
        # Provider always asks for another tool call -> never terminates on its own.
        looping = [
            ChatResult(content=f"thinking {i}", tool_calls=[ToolCall(id=f"c{i}", name="lookup", arguments={})])
            for i in range(10)
        ]
        provider = ScriptedProvider(looping)
        toolset = FakeToolset([_spec("lookup")])
        client = McpLlmClient(provider, [toolset], max_iterations=3)
        result = client.run("q")

        self.assertTrue(result.stopped_on_limit)
        self.assertEqual(result.iterations, 3)
        self.assertEqual(len(toolset.calls), 3)


if __name__ == "__main__":
    unittest.main()
