"""Tests for the OpenAI-compatible provider conversion logic.

A fake ``openai`` client is injected so no SDK, key, or network is needed.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from llm.provider.base import ChatMessage, ToolCall, ToolSpec  # noqa: E402
from llm.provider.local_provider import LocalProvider  # noqa: E402
from llm.provider.openai_compatible import OpenAICompatibleProvider  # noqa: E402


def _fake_response(content=None, tool_calls=None):
    message = SimpleNamespace(content=content, tool_calls=tool_calls)
    return SimpleNamespace(choices=[SimpleNamespace(message=message)])


class _FakeCompletions:
    def __init__(self, response):
        self._response = response
        self.last_kwargs = None

    def create(self, **kwargs):
        self.last_kwargs = kwargs
        return self._response


class _FakeClient:
    def __init__(self, response):
        self.chat = SimpleNamespace(completions=_FakeCompletions(response))


def _provider_with(response):
    provider = OpenAICompatibleProvider(api_key="sk-test", model="test-model")
    provider._client = _FakeClient(response)  # inject; bypasses lazy SDK build
    return provider


class TestOpenAICompatibleProvider(unittest.TestCase):
    def test_request_encodes_messages_and_tools(self):
        provider = _provider_with(_fake_response(content="ok"))
        tools = [
            ToolSpec(name="lookup", description="Look something up", parameters={"type": "object"})
        ]
        provider.chat([ChatMessage(role="user", content="hi")], tools)

        kwargs = provider.client.chat.completions.last_kwargs
        self.assertEqual(kwargs["model"], "test-model")
        self.assertEqual(kwargs["messages"][0], {"role": "user", "content": "hi"})
        self.assertEqual(kwargs["tool_choice"], "auto")
        self.assertEqual(kwargs["tools"][0]["function"]["name"], "lookup")

    def test_no_tools_omits_tool_kwargs(self):
        provider = _provider_with(_fake_response(content="ok"))
        provider.chat([ChatMessage(role="user", content="hi")], None)
        kwargs = provider.client.chat.completions.last_kwargs
        self.assertNotIn("tools", kwargs)
        self.assertNotIn("tool_choice", kwargs)

    def test_encodes_assistant_tool_calls_and_tool_result(self):
        provider = _provider_with(_fake_response(content="done"))
        messages = [
            ChatMessage(role="user", content="go"),
            ChatMessage(
                role="assistant",
                content=None,
                tool_calls=[ToolCall(id="call_1", name="lookup", arguments={"q": "x"})],
            ),
            ChatMessage(role="tool", content="result", tool_call_id="call_1", name="lookup"),
        ]
        provider.chat(messages, None)
        encoded = provider.client.chat.completions.last_kwargs["messages"]

        assistant = encoded[1]
        self.assertEqual(assistant["tool_calls"][0]["id"], "call_1")
        self.assertEqual(assistant["tool_calls"][0]["function"]["name"], "lookup")
        self.assertEqual(json.loads(assistant["tool_calls"][0]["function"]["arguments"]), {"q": "x"})

        tool_msg = encoded[2]
        self.assertEqual(tool_msg["role"], "tool")
        self.assertEqual(tool_msg["tool_call_id"], "call_1")

    def test_decodes_plain_text_response(self):
        provider = _provider_with(_fake_response(content="hello"))
        result = provider.chat([ChatMessage(role="user", content="hi")], None)
        self.assertEqual(result.content, "hello")
        self.assertEqual(result.tool_calls, [])

    def test_decodes_tool_call_response(self):
        raw_call = SimpleNamespace(
            id="call_9",
            function=SimpleNamespace(name="lookup", arguments='{"q": "abc", "n": 3}'),
        )
        provider = _provider_with(_fake_response(content=None, tool_calls=[raw_call]))
        result = provider.chat([ChatMessage(role="user", content="hi")], None)

        self.assertIsNone(result.content)
        self.assertEqual(len(result.tool_calls), 1)
        call = result.tool_calls[0]
        self.assertEqual(call.id, "call_9")
        self.assertEqual(call.name, "lookup")
        self.assertEqual(call.arguments, {"q": "abc", "n": 3})

    def test_malformed_tool_arguments_become_empty_dict(self):
        raw_call = SimpleNamespace(
            id="call_x", function=SimpleNamespace(name="lookup", arguments="not-json")
        )
        provider = _provider_with(_fake_response(tool_calls=[raw_call]))
        result = provider.chat([ChatMessage(role="user", content="hi")], None)
        self.assertEqual(result.tool_calls[0].arguments, {})


class TestProviderDefaults(unittest.TestCase):
    def test_local_provider_defaults(self):
        provider = LocalProvider()
        self.assertEqual(provider.name, "local")
        self.assertTrue(provider.base_url.endswith("/v1"))
        self.assertTrue(provider.model)  # has a default (Qwen)


if __name__ == "__main__":
    unittest.main()
