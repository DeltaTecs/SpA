from __future__ import annotations

import os
import re
from dataclasses import asdict
from functools import lru_cache
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from analysis_runner import run_phase_one_summary
from llm_analyzer import ScannerAnalyzer
from logging_setup import configure_logging
from mcp_client import MCPClient
from user_context import load_app_details, parse_intend_file


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


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/config")
def config() -> dict:
    provider = _provider(None)
    return {
        "provider": provider,
        "model": _model(provider, None),
    }


@app.get("/events", response_model=List[EventItem])
def list_events() -> List[EventItem]:
    try:
        text = _mcp_client().events()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"MCP event listing failed: {exc}") from exc
    return _parse_events(text)


@app.post("/phase1", response_model=ScanResponse)
def run_phase1(request: ScanRequest) -> ScanResponse:
    provider = _provider(request.provider)
    model = _model(provider, request.model)
    api_key = _api_key(provider, request.api_key)
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
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return ScanResponse(
        event_id=summary.event_id,
        recording_id=summary.recording_id,
        markdown=summary.to_markdown(),
        summary=asdict(summary),
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
        return request_provider
    env_provider = os.environ.get("SCANNER_PROVIDER") or os.environ.get("PROVIDER")
    if env_provider:
        return env_provider
    if os.environ.get("DEEPSEEK_API_KEY"):
        return "deepseek"
    return "ollama"


def _model(provider: str, request_model: Optional[str]) -> str:
    if request_model:
        return request_model
    env_model = os.environ.get("SCANNER_MODEL") or os.environ.get("MODEL")
    if env_model:
        return env_model
    defaults = {
        "gemini": "gemini-2.0-flash",
        "openai": "gpt-4o-mini",
        "deepseek": "deepseek-v4-flash",
        "ollama": "qwen3:8b",
    }
    return defaults.get(provider, "qwen3:8b")


def _api_key(provider: str, request_api_key: Optional[str]) -> Optional[str]:
    if request_api_key:
        return request_api_key
    if provider == "deepseek":
        return os.environ.get("DEEPSEEK_API_KEY") or os.environ.get("API_KEY")
    return os.environ.get("API_KEY")


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
