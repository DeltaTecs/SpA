from __future__ import annotations

import os
import re
from typing import Dict, List, Optional

from llm_analyzer import ScannerAnalyzer


PROVIDERS: Dict[str, dict] = {
    "ollama": {
        "label": "Ollama",
        "default_model": "qwen3:8b",
        "models": ("qwen3:8b", "qwen2.5:7b", "llama3.1:8b"),
        "model_envs": ("SCANNER_OLLAMA_MODELS", "OLLAMA_MODELS"),
        "api_key_envs": (),
    },
    "deepseek": {
        "label": "DeepSeek",
        "default_model": "deepseek-v4-flash",
        "models": ("deepseek-v4-flash", "deepseek-v4-pro"),
        "model_envs": ("SCANNER_DEEPSEEK_MODELS", "DEEPSEEK_MODELS"),
        "api_key_envs": ("DEEPSEEK_API_KEY",),
    },
    "openai": {
        "label": "OpenAI",
        "default_model": "gpt-4o-mini",
        "models": ("gpt-4o-mini", "gpt-4o"),
        "model_envs": ("SCANNER_OPENAI_MODELS", "OPENAI_MODELS"),
        "api_key_envs": ("OPENAI_API_KEY",),
    },
    "gemini": {
        "label": "Gemini",
        "default_model": "gemini-2.0-flash",
        "models": ("gemini-2.0-flash", "gemini-1.5-flash", "gemini-1.5-pro"),
        "model_envs": ("SCANNER_GEMINI_MODELS", "GEMINI_MODELS"),
        "api_key_envs": ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
    },
}


def resolve_provider(request_provider: Optional[str]) -> str:
    if request_provider:
        return request_provider.strip().lower()
    env_provider = os.environ.get("SCANNER_PROVIDER") or os.environ.get("PROVIDER")
    if env_provider:
        return env_provider.strip().lower()
    if os.environ.get("DEEPSEEK_API_KEY"):
        return "deepseek"
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    if os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"):
        return "gemini"
    return "ollama"


def resolve_model(provider: str, request_model: Optional[str]) -> str:
    if request_model:
        return request_model.strip()
    provider_key = provider.upper().replace("-", "_")
    env_model = (
        os.environ.get(f"SCANNER_{provider_key}_MODEL")
        or os.environ.get(f"{provider_key}_MODEL")
        or os.environ.get("SCANNER_MODEL")
        or os.environ.get("MODEL")
    )
    if env_model:
        return env_model
    return PROVIDERS.get(provider, PROVIDERS["ollama"])["default_model"]


def resolve_api_key(provider: str, request_api_key: Optional[str]) -> Optional[str]:
    if request_api_key:
        return request_api_key
    for env_name in PROVIDERS.get(provider, {}).get("api_key_envs", ()):
        value = os.environ.get(env_name)
        if value:
            return value
    return os.environ.get("API_KEY")


def resolve_api_base_url(provider: str, request_api_base_url: Optional[str]) -> Optional[str]:
    if request_api_base_url:
        return request_api_base_url
    if provider == "deepseek":
        return os.environ.get("DEEPSEEK_API_BASE_URL") or os.environ.get("API_BASE_URL")
    return os.environ.get("API_BASE_URL")


def provider_configs() -> List[dict]:
    return [_provider_config(provider_id) for provider_id in PROVIDERS]


def create_analyzer(
    *,
    provider: str,
    model: str,
    api_key: Optional[str],
    api_base_url: Optional[str],
) -> ScannerAnalyzer:
    analyzer = ScannerAnalyzer(
        model=model,
        ollama_host=os.environ.get("OLLAMA_HOST", "http://scanner-llm:11434"),
        provider=provider,
        api_key=api_key,
        api_base_url=api_base_url,
    )
    analyzer.initialize()
    return analyzer


def _provider_config(provider_id: str) -> dict:
    provider = PROVIDERS[provider_id]
    default_model = resolve_model(provider_id, None)
    models = _models(provider_id, default_model)
    has_api_key = bool(_configured_api_key_env(provider_id))
    available = not provider["api_key_envs"] or has_api_key
    if not available and _generic_api_key_applies(provider_id):
        has_api_key = True
        available = True
    return {
        "id": provider_id,
        "label": provider["label"],
        "available": available,
        "has_api_key": has_api_key,
        "default_model": default_model,
        "models": models,
    }


def _models(provider_id: str, default_model: str) -> List[str]:
    provider = PROVIDERS[provider_id]
    models: List[str] = []
    for env_name in provider["model_envs"]:
        raw = os.environ.get(env_name)
        if raw:
            models.extend(
                model.strip()
                for model in re.split(r"[,;\s]+", raw)
                if model.strip()
            )
            break
    if not models:
        models.extend(provider["models"])
    if default_model not in models:
        models.insert(0, default_model)
    return models


def _configured_api_key_env(provider_id: str) -> Optional[str]:
    for env_name in PROVIDERS[provider_id]["api_key_envs"]:
        if os.environ.get(env_name):
            return env_name
    return None


def _generic_api_key_applies(provider_id: str) -> bool:
    env_provider = os.environ.get("SCANNER_PROVIDER") or os.environ.get("PROVIDER")
    return bool(
        os.environ.get("API_KEY")
        and env_provider
        and env_provider.strip().lower() == provider_id
    )
