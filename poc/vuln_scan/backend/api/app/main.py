from __future__ import annotations

import os
import re
from functools import lru_cache
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from analysis_runner import run_phase_one_summary
from llm_analyzer import ScannerAnalyzer
from logging_setup import configure_logging
from mcp_client import MCPClient
from user_context import load_app_details, parse_intend_file

from .prescan_store import get_prescan, list_prescans, prescan_dict, save_prescan


configure_logging()

app = FastAPI(title="Vulnerability Scanner API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class EventItem(BaseModel):
    event_id: int
    description: str
    start_timestamp: Optional[int] = None
    end_timestamp: Optional[int] = None
    packet_count: int = 0
    recording_ids: List[int] = Field(default_factory=list)


class ScanRequest(BaseModel):
    event_id: int
    provider: Optional[str] = None
    model: Optional[str] = None
    api_key: Optional[str] = None
    api_base_url: Optional[str] = None


class ScanResponse(BaseModel):
    event_id: int
    recording_id: Optional[int]
    markdown: str
    summary: dict


class PreScanItem(BaseModel):
    event_id: int
    recording_id: Optional[int] = None
    most_interesting_packet_id: Optional[int] = None
    packet_content: str = ""
    event_summary: str = ""
    suspected_trigger: str = ""
    entrypoint_rationale: str = ""
    supporting_packet_ids: List[int] = Field(default_factory=list)


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


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/config")
def config() -> dict:
    provider = _provider(None)
    model = _model(provider, None)
    providers = [_provider_config(provider_id) for provider_id in PROVIDERS]
    if not any(item["id"] == provider and item["available"] for item in providers):
        provider = next((item["id"] for item in providers if item["available"]), provider)
        model = _model(provider, None)
    return {
        "provider": provider,
        "model": model,
        "providers": providers,
    }


@app.get("/events", response_model=List[EventItem])
def list_events() -> List[EventItem]:
    try:
        text = _mcp_client().events()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"MCP event listing failed: {exc}") from exc
    return _parse_events(text)


@app.get("/prescans", response_model=List[PreScanItem])
def prescans() -> List[PreScanItem]:
    return [PreScanItem(**row) for row in list_prescans()]


@app.get("/prescans/{event_id}", response_model=ScanResponse)
def prescan(event_id: int) -> ScanResponse:
    summary = get_prescan(event_id)
    if summary is None:
        raise HTTPException(status_code=404, detail=f"No PreScan for event_id {event_id}")
    return ScanResponse(
        event_id=summary.event_id,
        recording_id=summary.recording_id,
        markdown=summary.to_markdown(),
        summary=prescan_dict(summary),
    )


@app.post("/phase1", response_model=ScanResponse)
def run_phase1(request: ScanRequest) -> ScanResponse:
    provider = _provider(request.provider)
    if provider not in PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Unsupported provider: {provider}")
    model = _model(provider, request.model)
    api_key = _api_key(provider, request.api_key)
    if PROVIDERS[provider]["api_key_envs"] and not api_key:
        raise HTTPException(
            status_code=400,
            detail=f"{PROVIDERS[provider]['label']} API key is not configured",
        )
    api_base_url = request.api_base_url or os.environ.get("API_BASE_URL")
    if provider == "deepseek" and not api_base_url:
        api_base_url = os.environ.get("DEEPSEEK_API_BASE_URL")

    try:
        analyzer = ScannerAnalyzer(
            model=model,
            ollama_host=os.environ.get("OLLAMA_HOST", "http://scanner-llm:11434"),
            provider=provider,
            api_key=api_key,
            api_base_url=api_base_url,
        )
        analyzer.initialize()
        summary = run_phase_one_summary(
            mcp_client=_mcp_client(),
            analyzer=analyzer,
            event_id=request.event_id,
            app_details=_optional_app_details(),
            user_actions=_optional_user_actions(),
        )
        save_prescan(summary)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return ScanResponse(
        event_id=summary.event_id,
        recording_id=summary.recording_id,
        markdown=summary.to_markdown(),
        summary=prescan_dict(summary),
    )


@app.post("/phase2", status_code=501)
def run_phase2() -> dict:
    raise HTTPException(
        status_code=501,
        detail="Phase two is intentionally not implemented yet.",
    )


@lru_cache(maxsize=1)
def _mcp_client() -> MCPClient:
    return MCPClient(base_url=os.environ.get("MCP_URL", "http://mcp-packet-db:8765"))


def _provider(request_provider: Optional[str]) -> str:
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


def _model(provider: str, request_model: Optional[str]) -> str:
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


def _api_key(provider: str, request_api_key: Optional[str]) -> Optional[str]:
    if request_api_key:
        return request_api_key
    for env_name in PROVIDERS.get(provider, {}).get("api_key_envs", ()):
        value = os.environ.get(env_name)
        if value:
            return value
    return os.environ.get("API_KEY")


def _provider_config(provider_id: str) -> dict:
    provider = PROVIDERS[provider_id]
    default_model = _model(provider_id, None)
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


def _optional_app_details() -> Optional[str]:
    path = os.environ.get("APP_DETAILS")
    if not path or not os.path.exists(path):
        return None
    return load_app_details(path)


def _optional_user_actions():
    path = os.environ.get("USER_INTEND")
    if not path or not os.path.exists(path):
        return None
    return parse_intend_file(path)


def _parse_events(text: str) -> List[EventItem]:
    if text.strip() == "(no events yet)":
        return []

    events: List[EventItem] = []
    pattern = re.compile(
        r"^event_id:(?P<event_id>\d+)\s+description:(?P<description>.*?)\s+"
        r"start:(?P<start>\S+)\s+end:(?P<end>\S+)\s+"
        r"packets:(?P<packets>\d+)\s+recording_ids:(?P<recording_ids>[^\s]*)$"
    )
    for line in text.splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        recording_ids = [
            int(value)
            for value in match.group("recording_ids").split(",")
            if value.strip().isdigit()
        ]
        events.append(
            EventItem(
                event_id=int(match.group("event_id")),
                description=match.group("description").strip(),
                start_timestamp=_nullable_int(match.group("start")),
                end_timestamp=_nullable_int(match.group("end")),
                packet_count=int(match.group("packets")),
                recording_ids=recording_ids,
            )
        )
    return events


def _nullable_int(value: str) -> Optional[int]:
    if value in {"", "None", "none", "NULL", "null"}:
        return None
    try:
        return int(value)
    except ValueError:
        return None
