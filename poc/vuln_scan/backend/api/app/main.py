from __future__ import annotations

import os
import re
import threading
from functools import lru_cache
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from analysis_types import ALLOWED_ANALYSIS_TYPES, DEFAULT_ANALYSIS_TYPE
from phase1_runner import run_phase_one_summary
from logging_setup import configure_logging
from mcp_client import MCPClient
from mcp_proxy_tools import analysis_mcp_server_specs_from_env
from phase2_runner import run_phase_two_analysis
from scanner_config import (
    PROVIDERS,
    create_analyzer,
    provider_configs,
    resolve_api_base_url,
    resolve_api_key,
    resolve_model,
    resolve_provider,
)
from user_context import load_app_details, parse_intend_file, parse_intend_text

from .analysis_sessions import AnalysisRun, AnalysisSessionStore
from .prescan_store import get_prescan, list_prescans, prescan_dict, save_prescan
from .scan_store import (
    get_phase_two_scans,
    list_phase_two_scans,
    save_completed_phase_two_scan,
)


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
    app_details_content: Optional[str] = None
    user_intend_content: Optional[str] = None


class ScanResponse(BaseModel):
    event_id: int
    recording_id: Optional[int]
    markdown: str
    summary: dict


class PhaseTwoRequest(BaseModel):
    event_id: int
    analysis_types: List[str] = Field(default_factory=lambda: [DEFAULT_ANALYSIS_TYPE])
    constraints: str = ""
    auto_approve_mcp_database_requests: bool = False
    auto_approve_all_mcp_requests: bool = False
    provider: Optional[str] = None
    model: Optional[str] = None
    api_key: Optional[str] = None
    api_base_url: Optional[str] = None
    app_details_content: Optional[str] = None
    user_intend_content: Optional[str] = None
    prior_report_ids: List[int] = Field(default_factory=list)


class ToolDecisionRequest(BaseModel):
    approved: bool


class StoredPhaseOneItem(BaseModel):
    event_id: int
    recording_id: Optional[int] = None
    most_interesting_packet_id: Optional[int] = None
    packet_content: str = ""
    event_summary: str = ""
    suspected_trigger: str = ""
    entrypoint_rationale: str = ""
    supporting_packet_ids: List[int] = Field(default_factory=list)


class StoredScanReportItem(BaseModel):
    scan_id: int
    scan_type_id: int
    scan_type_title: str
    scan_type_prompt: str = ""
    event_id: int
    llm_provider: str = ""
    llm_model: str = ""
    user_constrains: str = ""
    tools_used: str = ""
    summary: str = ""


analysis_runs = AnalysisSessionStore()


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/config")
def config() -> dict:
    provider = resolve_provider(None)
    model = resolve_model(provider, None)
    providers = provider_configs()
    if not any(item["id"] == provider and item["available"] for item in providers):
        provider = next((item["id"] for item in providers if item["available"]), provider)
        model = resolve_model(provider, None)
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


@app.get("/prescans", response_model=List[StoredPhaseOneItem])
def prescans() -> List[StoredPhaseOneItem]:
    return [StoredPhaseOneItem(**row) for row in list_prescans()]


@app.get("/prescans/{event_id}", response_model=ScanResponse)
def prescan(event_id: int) -> ScanResponse:
    summary = get_prescan(event_id)
    if summary is None:
        raise HTTPException(status_code=404, detail=f"No pre_scan for event_id {event_id}")
    return ScanResponse(
        event_id=summary.event_id,
        recording_id=summary.recording_id,
        markdown=summary.to_markdown(),
        summary=prescan_dict(summary),
    )


@app.get("/events/{event_id}/scans", response_model=List[StoredScanReportItem])
def stored_scan_reports(event_id: int) -> List[StoredScanReportItem]:
    return [StoredScanReportItem(**row) for row in list_phase_two_scans(event_id)]


@app.post("/phase1", response_model=ScanResponse)
def run_phase1(request: ScanRequest) -> ScanResponse:
    provider, model, api_key, api_base_url = _llm_settings(request)

    try:
        analyzer = create_analyzer(
            provider=provider,
            model=model,
            api_key=api_key,
            api_base_url=api_base_url,
        )
        summary = run_phase_one_summary(
            mcp_client=_mcp_client(),
            analyzer=analyzer,
            event_id=request.event_id,
            app_details=_optional_app_details(request),
            user_actions=_optional_user_actions(request),
        )
        save_prescan(summary)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return ScanResponse(
        event_id=summary.event_id,
        recording_id=summary.recording_id,
        markdown=summary.to_markdown(),
        summary=prescan_dict(summary),
    )


@app.post("/phase2")
def start_phase2(request: PhaseTwoRequest) -> dict:
    provider, model, api_key, api_base_url = _llm_settings(request)
    analysis_types = _analysis_types(request.analysis_types)
    if get_prescan(request.event_id) is None:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Event {request.event_id} has no completed pre-scan; "
                "run the pre-scan before starting vulnerability analysis."
            ),
        )
    run = analysis_runs.create(
        event_id=request.event_id,
        analysis_types=analysis_types,
        constraints=request.constraints,
        provider=provider,
        model=model,
        approval_timeout_seconds=float(
            os.environ.get("PHASE2_APPROVAL_TIMEOUT_SECONDS", "3600")
        ),
        auto_approve_mcp_database_requests=request.auto_approve_mcp_database_requests,
        auto_approve_all_mcp_requests=request.auto_approve_all_mcp_requests,
    )

    thread = threading.Thread(
        target=_run_phase2_background,
        args=(run, request, provider, model, api_key, api_base_url),
        daemon=True,
    )
    thread.start()
    return run.snapshot()


@app.get("/phase2/{run_id}")
def phase2_status(run_id: str) -> dict:
    run = _analysis_run(run_id)
    return run.snapshot()


@app.post("/phase2/{run_id}/abort")
def abort_phase2(run_id: str) -> dict:
    run = _analysis_run(run_id)
    run.abort()
    return run.snapshot()


@app.post("/phase2/{run_id}/tool/stop")
def stop_phase2_tool(run_id: str) -> dict:
    run = _analysis_run(run_id)
    if not run.request_active_tool_stop():
        raise HTTPException(status_code=409, detail="No MCP tool is currently running")
    return run.snapshot()


@app.post("/phase2/{run_id}/tool-requests/{request_id}/decision")
def decide_phase2_tool(
    run_id: str,
    request_id: str,
    request: ToolDecisionRequest,
) -> dict:
    run = _analysis_run(run_id)
    try:
        run.decide_tool_request(request_id, request.approved)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Tool request not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return run.snapshot()


@lru_cache(maxsize=1)
def _mcp_client() -> MCPClient:
    return MCPClient(base_url=os.environ.get("MCP_URL", "http://mcp-packet-db:8765"))


def _llm_settings(request: ScanRequest | PhaseTwoRequest):
    provider = resolve_provider(request.provider)
    if provider not in PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Unsupported provider: {provider}")
    model = resolve_model(provider, request.model)
    api_key = resolve_api_key(provider, request.api_key)
    if PROVIDERS[provider]["api_key_envs"] and not api_key:
        raise HTTPException(
            status_code=400,
            detail=f"{PROVIDERS[provider]['label']} API key is not configured",
        )
    api_base_url = resolve_api_base_url(provider, request.api_base_url)
    return provider, model, api_key, api_base_url


def _analysis_types(raw_types: List[str]) -> List[str]:
    types = [item.strip() for item in raw_types if item.strip()]
    if not types:
        return [DEFAULT_ANALYSIS_TYPE]
    invalid = [item for item in types if item not in ALLOWED_ANALYSIS_TYPES]
    if invalid:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported analysis type: {invalid[0]}",
        )
    if len(types) > 1:
        raise HTTPException(
            status_code=400,
            detail="Select exactly one vulnerability analysis type.",
        )
    return types


def _analysis_run(run_id: str) -> AnalysisRun:
    run = analysis_runs.get(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Analysis run not found")
    return run


def _run_phase2_background(
    run: AnalysisRun,
    request: PhaseTwoRequest,
    provider: str,
    model: str,
    api_key: Optional[str],
    api_base_url: Optional[str],
) -> None:
    run.start()
    try:
        analyzer = create_analyzer(
            provider=provider,
            model=model,
            api_key=api_key,
            api_base_url=api_base_url,
        )
        prescan_summary = get_prescan(request.event_id)
        prescan_markdown = prescan_summary.to_markdown() if prescan_summary else ""
        if prescan_markdown:
            run.add_progress("Loaded stored phase-one summary.")

        prior_reports_markdown = _prior_reports_markdown(request.prior_report_ids)
        if prior_reports_markdown:
            run.add_progress(
                f"Loaded {len(request.prior_report_ids)} prior scan report(s) into the prompt."
            )

        packet_mcp_client = MCPClient(
            base_url=os.environ.get("MCP_URL", "http://mcp-packet-db:8765"),
            connect_timeout=30,
            default_timeout=float(os.environ.get("PHASE2_MCP_TOOL_TIMEOUT_SECONDS", "900")),
        )
        result = run_phase_two_analysis(
            packet_mcp_client=packet_mcp_client,
            analyzer=analyzer,
            event_id=request.event_id,
            analysis_types=run.analysis_types,
            constraints=request.constraints,
            mcp_servers=analysis_mcp_server_specs_from_env(),
            approval_callback=run.request_tool_permission,
            progress_callback=run.add_progress,
            tool_start_callback=run.start_tool_execution,
            tool_stop_requested_callback=run.is_tool_stop_requested,
            tool_finish_callback=run.finish_tool_execution,
            app_details=_optional_app_details(request),
            user_actions=_optional_user_actions(request),
            prescan_markdown=prescan_markdown,
            prior_reports_markdown=prior_reports_markdown,
        )
        if run.abort_requested:
            run.complete("")
            return
        scan_id = save_completed_phase_two_scan(
            scan_type_title=(
                run.analysis_types[0] if run.analysis_types else DEFAULT_ANALYSIS_TYPE
            ),
            event_id=run.event_id,
            llm_provider=run.provider,
            llm_model=run.model,
            user_constraints=run.constraints,
            tools_used=run.tools_used(),
            summary=result,
        )
        run.add_progress(f"Stored phase-two scan report: scan_id {scan_id}.")
        run.complete(result)
    except Exception as exc:
        if run.abort_requested:
            run.complete("")
            return
        run.fail(str(exc))


def _prior_reports_markdown(scan_ids: List[int]) -> str:
    if not scan_ids:
        return ""
    rows = get_phase_two_scans(scan_ids)
    rows_by_id = {int(row["scan_id"]): row for row in rows}
    sections: List[str] = []
    for scan_id in scan_ids:
        row = rows_by_id.get(int(scan_id))
        if row is None:
            continue
        title = row.get("scan_type_title") or "Unknown scan type"
        provider = row.get("llm_provider") or "provider"
        model = row.get("llm_model") or "model"
        body = (row.get("summary") or "").strip() or "(empty report)"
        sections.append(
            f"--- Prior report #{row['scan_id']} ({title}; {provider} / {model}; event {row['event_id']}) ---\n"
            f"{body}"
        )
    return "\n\n".join(sections)


def _optional_app_details(request: ScanRequest | PhaseTwoRequest) -> Optional[str]:
    if request.app_details_content is not None:
        return request.app_details_content.strip() or None

    resolved_path = _context_file_path("APP_DETAILS")
    if resolved_path is None:
        return None
    return load_app_details(resolved_path)


def _optional_user_actions(request: ScanRequest | PhaseTwoRequest):
    if request.user_intend_content is not None:
        return parse_intend_text(request.user_intend_content, "uploaded user intend file")

    resolved_path = _context_file_path("USER_INTEND")
    if resolved_path is None:
        return None
    return parse_intend_file(resolved_path)


def _context_file_path(env_name: str) -> Optional[str]:
    candidate = os.environ.get(env_name)
    if candidate is None:
        return None

    candidate = candidate.strip()
    if not candidate:
        return None

    if not os.path.isfile(candidate):
        return None
    return candidate


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
