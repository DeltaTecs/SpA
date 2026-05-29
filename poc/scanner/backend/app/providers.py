"""LLM provider catalogue for the configuration UI.

Combines the provider types the ``llm`` package supports with a small static
catalogue of model options, so the frontend can offer a provider + model picker.
"""

from __future__ import annotations

from typing import List

from llm import ProviderFactory

from .schemas import ProviderOption, ReasoningEffort

#: Provider types that authenticate with an API key (mirrors the llm factory).
_KEYED_PROVIDERS = {"openai", "deepseek"}

#: A few sensible model options per provider; the first is the default. Local
#: providers also accept a free-text model override in the UI.
_MODEL_CATALOG = {
    "openai": ["gpt-4o-mini", "gpt-4o"],
    "deepseek": [
        "deepseek-v4-flash",
        "deepseek-v4-pro",
        "deepseek-chat",
        "deepseek-reasoner",
    ],
    "local": ["qwen2.5"],
    "qwen": ["qwen2.5"],
}

_REASONING_EFFORT_CATALOG: dict[str, list[ReasoningEffort]] = {
    "deepseek": ["high", "max"],
}


def list_providers() -> List[ProviderOption]:
    """Return the selectable providers with their models and key requirement."""
    options: List[ProviderOption] = []
    for provider_type in ProviderFactory.supported_types():
        models = _MODEL_CATALOG.get(provider_type, [])
        reasoning_efforts = _REASONING_EFFORT_CATALOG.get(provider_type, [])
        options.append(
            ProviderOption(
                type=provider_type,
                requires_key=provider_type in _KEYED_PROVIDERS,
                default_model=models[0] if models else None,
                model_options=models,
                reasoning_effort_options=reasoning_efforts,
            )
        )
    return options


def validate_reasoning_effort(provider_type: str, effort: ReasoningEffort | None) -> None:
    """Reject effort values the selected provider catalogue does not advertise."""
    if effort is None:
        return
    provider_key = (provider_type or "").strip().lower()
    supported = _REASONING_EFFORT_CATALOG.get(provider_key, [])
    if effort not in supported:
        supported_label = ", ".join(supported) if supported else "none"
        raise ValueError(
            f"Provider '{provider_key}' does not support reasoning_effort={effort!r}. "
            f"Supported values: {supported_label}."
        )
