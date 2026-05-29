"""Local provider for self-hosted, OpenAI-compatible model servers.

Targets local runtimes such as Ollama, LM Studio or vLLM that expose an
OpenAI-compatible ``/v1`` endpoint and serve models like Qwen. No API key is
required; the local server typically ignores authentication entirely.
"""

from __future__ import annotations

import os

from .openai_compatible import OpenAICompatibleProvider

#: Default endpoint for a local Ollama-style OpenAI-compatible server.
DEFAULT_BASE_URL = "http://localhost:11434/v1"

#: Default local model (Qwen). Override per-call or via ``LOCAL_LLM_MODEL``.
DEFAULT_MODEL = "qwen2.5"


class LocalProvider(OpenAICompatibleProvider):
    """LLM provider backed by a local OpenAI-compatible server (e.g. Qwen)."""

    name = "local"

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str | None = None,
        base_url: str | None = None,
        reasoning_effort: str | None = None,
        timeout: float = 60.0,
    ) -> None:
        super().__init__(
            # Local servers do not need a key; keep whatever was passed (if any).
            api_key=api_key,
            model=model or os.environ.get("LOCAL_LLM_MODEL", DEFAULT_MODEL),
            base_url=base_url or os.environ.get("LOCAL_LLM_BASE_URL", DEFAULT_BASE_URL),
            reasoning_effort=reasoning_effort,
            timeout=timeout,
        )
