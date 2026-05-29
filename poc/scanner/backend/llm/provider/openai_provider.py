"""OpenAI provider."""

from __future__ import annotations

from .openai_compatible import OpenAICompatibleProvider

#: Default model used when the caller does not specify one.
DEFAULT_MODEL = "gpt-4o-mini"


class OpenAIProvider(OpenAICompatibleProvider):
    """LLM provider backed by the OpenAI API (api.openai.com)."""

    name = "openai"

    def __init__(
        self,
        *,
        api_key: str | None,
        model: str | None = None,
        base_url: str | None = None,
        timeout: float = 60.0,
    ) -> None:
        # base_url=None lets the openai SDK use its built-in default endpoint.
        super().__init__(
            api_key=api_key,
            model=model or DEFAULT_MODEL,
            base_url=base_url,
            timeout=timeout,
        )
