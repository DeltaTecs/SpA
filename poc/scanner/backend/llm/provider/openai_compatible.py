"""Shared implementation for OpenAI-API-compatible providers.

OpenAI, DeepSeek and most local servers (Ollama / LM Studio / vLLM) all speak
the OpenAI Chat Completions API, so they share this single implementation built
on the official ``openai`` SDK. Concrete providers differ only in their default
``model`` and ``base_url`` (see the sibling modules).
"""

from __future__ import annotations

import json
import logging
from typing import Any

from ..logging_config import log_payload
from .base import BaseProvider, ChatMessage, ChatResult, ToolCall, ToolSpec

logger = logging.getLogger(__name__)


class OpenAICompatibleProvider(BaseProvider):
    """A provider that talks to any OpenAI-compatible Chat Completions endpoint."""

    name = "openai-compatible"

    def __init__(
        self,
        *,
        api_key: str | None,
        model: str,
        base_url: str | None = None,
        timeout: float = 60.0,
    ) -> None:
        super().__init__(api_key=api_key, model=model, base_url=base_url, timeout=timeout)
        # The SDK client is built lazily so constructing a provider (e.g. in the
        # factory or in tests) never requires network access or a real key.
        self._client: Any | None = None

    @property
    def client(self) -> Any:
        """Return the (lazily constructed) ``openai`` client."""

        if self._client is None:
            self._client = self._build_client()
        return self._client

    def _build_client(self) -> Any:
        try:
            from openai import OpenAI
        except ImportError as exc:  # pragma: no cover - depends on environment
            raise RuntimeError(
                "The 'openai' package is required for OpenAI-compatible providers. "
                "Install it with: pip install openai"
            ) from exc

        # Local servers often ignore the key but the SDK still requires a value.
        api_key = self.api_key or "not-needed"
        logger.debug("Building openai client (base_url=%s, timeout=%s)", self.base_url, self.timeout)
        return OpenAI(api_key=api_key, base_url=self.base_url, timeout=self.timeout)

    def chat(
        self,
        messages: list[ChatMessage],
        tools: list[ToolSpec] | None = None,
    ) -> ChatResult:
        payload_messages = [self._encode_message(message) for message in messages]
        payload_tools = [self._encode_tool(tool) for tool in tools] if tools else None

        tool_names = [tool.name for tool in tools] if tools else []
        logger.info(
            "LLM request provider=%s model=%s messages=%d tools=%s",
            self.name,
            self.model,
            len(payload_messages),
            tool_names,
        )
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("LLM request payload=%s", log_payload(payload_messages))

        kwargs: dict[str, Any] = {"model": self.model, "messages": payload_messages}
        if payload_tools:
            kwargs["tools"] = payload_tools
            kwargs["tool_choice"] = "auto"

        response = self.client.chat.completions.create(**kwargs)
        result = self._decode_response(response)

        logger.info(
            "LLM response provider=%s tool_calls=%d has_content=%s",
            self.name,
            len(result.tool_calls),
            result.content is not None,
        )
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("LLM response content=%s", log_payload(result.content))
        return result

    # -- encoding (our dataclasses -> OpenAI payloads) ----------------------

    @staticmethod
    def _encode_message(message: ChatMessage) -> dict[str, Any]:
        encoded: dict[str, Any] = {"role": message.role}
        # Assistant tool-call messages may legitimately have null content.
        encoded["content"] = message.content
        if message.tool_calls:
            encoded["tool_calls"] = [
                {
                    "id": call.id,
                    "type": "function",
                    "function": {
                        "name": call.name,
                        "arguments": json.dumps(call.arguments),
                    },
                }
                for call in message.tool_calls
            ]
        if message.tool_call_id is not None:
            encoded["tool_call_id"] = message.tool_call_id
        if message.name is not None:
            encoded["name"] = message.name
        return encoded

    @staticmethod
    def _encode_tool(tool: ToolSpec) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.parameters or {"type": "object", "properties": {}},
            },
        }

    # -- decoding (OpenAI response -> our dataclasses) ----------------------

    @classmethod
    def _decode_response(cls, response: Any) -> ChatResult:
        choice = response.choices[0]
        message = choice.message
        content = getattr(message, "content", None)

        tool_calls: list[ToolCall] = []
        for raw_call in getattr(message, "tool_calls", None) or []:
            function = raw_call.function
            tool_calls.append(
                ToolCall(
                    id=raw_call.id,
                    name=function.name,
                    arguments=cls._parse_arguments(function.arguments),
                )
            )
        return ChatResult(content=content, tool_calls=tool_calls)

    @staticmethod
    def _parse_arguments(raw: str | None) -> dict:
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            logger.warning("Could not JSON-decode tool arguments: %r", raw)
            return {}
        return parsed if isinstance(parsed, dict) else {"value": parsed}
