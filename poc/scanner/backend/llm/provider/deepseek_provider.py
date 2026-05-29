"""DeepSeek provider (OpenAI-compatible API)."""

from __future__ import annotations

from typing import Any

from .openai_compatible import OpenAICompatibleProvider

#: DeepSeek's OpenAI-compatible endpoint.
DEFAULT_BASE_URL = "https://api.deepseek.com"

#: Default model used when the caller does not specify one.
DEFAULT_MODEL = "deepseek-v4-flash"


class DeepSeekProvider(OpenAICompatibleProvider):
    """LLM provider backed by the DeepSeek API."""

    name = "deepseek"

    def __init__(
        self,
        *,
        api_key: str | None,
        model: str | None = None,
        base_url: str | None = None,
        reasoning_effort: str | None = None,
        timeout: float = 60.0,
    ) -> None:
        super().__init__(
            api_key=api_key,
            model=model or DEFAULT_MODEL,
            base_url=base_url or DEFAULT_BASE_URL,
            reasoning_effort=reasoning_effort,
            timeout=timeout,
        )

    def _chat_extra_kwargs(self) -> dict[str, Any]:
        kwargs = super()._chat_extra_kwargs()
        if self.reasoning_effort is not None:
            kwargs["extra_body"] = {"thinking": {"type": "enabled"}}
        return kwargs
