"""LLM provider catalogue for the configuration UI.

Combines the provider types the ``llm`` package supports with a small static
catalogue of model options, so the frontend can offer a provider + model picker.
"""

from __future__ import annotations

from typing import List

from llm import ProviderFactory

from .schemas import ProviderOption

#: Provider types that authenticate with an API key (mirrors the llm factory).
_KEYED_PROVIDERS = {"openai", "deepseek"}

#: A few sensible model options per provider; the first is the default. Local
#: providers also accept a free-text model override in the UI.
_MODEL_CATALOG = {
    "openai": ["gpt-4o-mini", "gpt-4o"],
    "deepseek": ["deepseek-chat", "deepseek-reasoner"],
    "local": ["qwen2.5"],
    "qwen": ["qwen2.5"],
}


def list_providers() -> List[ProviderOption]:
    """Return the selectable providers with their models and key requirement."""
    options: List[ProviderOption] = []
    for provider_type in ProviderFactory.supported_types():
        models = _MODEL_CATALOG.get(provider_type, [])
        options.append(
            ProviderOption(
                type=provider_type,
                requires_key=provider_type in _KEYED_PROVIDERS,
                default_model=models[0] if models else None,
                model_options=models,
            )
        )
    return options
