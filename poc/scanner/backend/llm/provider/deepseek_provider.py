"""DeepSeek provider (OpenAI-compatible API)."""

from __future__ import annotations

from .openai_compatible import OpenAICompatibleProvider

#: DeepSeek's OpenAI-compatible endpoint.
DEFAULT_BASE_URL = "https://api.deepseek.com"

#: Default model used when the caller does not specify one.
DEFAULT_MODEL = "deepseek-chat"


class DeepSeekProvider(OpenAICompatibleProvider):
    """LLM provider backed by the DeepSeek API."""

    name = "deepseek"

    def __init__(
        self,
        *,
        api_key: str | None,
        model: str | None = None,
        base_url: str | None = None,
        timeout: float = 60.0,
    ) -> None:
        super().__init__(
            api_key=api_key,
            model=model or DEFAULT_MODEL,
            base_url=base_url or DEFAULT_BASE_URL,
            timeout=timeout,
        )
