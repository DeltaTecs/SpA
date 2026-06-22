"""Factory for constructing LLM providers.

The factory is the single entry point for creating providers. It is handed the
API key for the chosen provider and forwards it to the constructed object.
Local providers do not require a key (see :class:`LocalProvider`).
"""

from __future__ import annotations

import logging

from .base import BaseProvider
from .deepseek_provider import DeepSeekProvider
from .local_provider import LocalProvider
from .openai_provider import OpenAIProvider

logger = logging.getLogger(__name__)

#: Provider types that authenticate with an API key (key is mandatory).
_KEYED_PROVIDERS = {
    "openai": OpenAIProvider,
    "deepseek": DeepSeekProvider,
}

#: Provider types that do not require an API key.
_KEYLESS_PROVIDERS = {
    "local": LocalProvider,
    "qwen": LocalProvider,  # convenience alias for the default local model
}


class ProviderFactory:
    """Creates :class:`BaseProvider` instances from a provider type + API key."""

    @staticmethod
    def supported_types() -> list[str]:
        """Return the sorted list of recognised provider type identifiers."""

        return sorted({*_KEYED_PROVIDERS, *_KEYLESS_PROVIDERS})

    @staticmethod
    def create(
        provider_type: str,
        api_key: str | None = None,
        *,
        model: str | None = None,
        base_url: str | None = None,
        reasoning_effort: str | None = None,
        timeout: float = 60.0,
    ) -> BaseProvider:
        """Create a provider.

        Args:
            provider_type: One of :meth:`supported_types` (case-insensitive).
            api_key: The provider's API key. Required for ``openai``/``deepseek``;
                ignored/optional for local providers.
            model: Optional model override (otherwise the provider's default).
            base_url: Optional endpoint override.
            reasoning_effort: Optional provider-specific reasoning effort.
            timeout: Request timeout in seconds.

        Raises:
            ValueError: If the type is unknown, or a key is required but missing.
        """

        key = (provider_type or "").strip().lower()
        logger.debug(
            "Creating provider type=%s (model=%s, base_url=%s, reasoning_effort=%s)",
            key,
            model,
            base_url,
            reasoning_effort,
        )

        if key in _KEYED_PROVIDERS:
            if not api_key or not api_key.strip():
                raise ValueError(f"Provider '{key}' requires a non-empty api_key.")
            provider_cls = _KEYED_PROVIDERS[key]
        elif key in _KEYLESS_PROVIDERS:
            provider_cls = _KEYLESS_PROVIDERS[key]
        else:
            raise ValueError(
                f"Unknown provider type '{provider_type}'. "
                f"Supported: {', '.join(ProviderFactory.supported_types())}."
            )

        provider = provider_cls(
            api_key=api_key,
            model=model,
            base_url=base_url,
            reasoning_effort=reasoning_effort,
            timeout=timeout,
        )
        logger.info("Created provider %s (model=%s)", provider.name, provider.model)
        return provider
