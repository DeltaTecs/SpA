from __future__ import annotations

import logging
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from functools import lru_cache
from typing import Callable, List, Optional, Sequence

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from analysis_types import ALLOWED_ANALYSIS_TYPES, DEFAULT_ANALYSIS_TYPE
from phase1_runner import run_phase_one_summary
from logging_setup import configure_logging
from mcp_client import MCPClient
from mcp_proxy_tools import analysis_mcp_server_specs_from_env
from phase2_runner import run_phase_two_analysis
from scan_logger import ScanRunLogger, create_scan_run_logger
from smart_approver import SmartToolApprover
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

from .analysis_runs import (
    APPROVAL_MODE_MANUAL,
    APPROVAL_MODE_SMART_NON_DB,
    APPROVAL_MODES,
    AnalysisRun,
    AnalysisSessionStore,
)
from .prescan_sessions import PrescanRun, PrescanSessionStore
from .prescan_store import get_prescan, list_prescans, prescan_dict, save_prescan
from .scan_store import (
    clear_scan_condensed_summary,
    get_phase_two_scans,
    list_phase_two_scans,
    save_completed_phase_two_scan,
    set_scan_condensed_summary,
)


configure_logging()
logger = logging.getLogger(__name__)

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
    enable_web_search: bool = False
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
    approval_mode: str = APPROVAL_MODE_MANUAL
    approval_provider: Optional[str] = None
    approval_model: Optional[str] = None
    escalate_smart_rejections: bool = True
    provider: Optional[str] = None
    model: Optional[str] = None
    api_key: Optional[str] = None
    api_base_url: Optional[str] = None
    app_details_content: Optional[str] = None
    user_intend_content: Optional[str] = None
    prior_report_ids: List[int] = Field(default_factory=list)
    compact_included_reports: bool = False
    max_reasoning_effort: bool = False
    unlimited_rounds: bool = False


class ToolDecisionRequest(BaseModel):
    approved: bool
    reason: Optional[str] = None


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
    condensed_summary: str = ""


@dataclass(frozen=True)
class PriorReportSection:
    scan_id: int
    label: str
    markdown: str
    condensed_summary: str = ""


analysis_runs = AnalysisSessionStore()
prescan_runs = PrescanSessionStore()
_phase1_loggers: dict[str, ScanRunLogger] = {}
_phase2_loggers: dict[str, ScanRunLogger] = {}


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


@app.delete("/scans/{scan_id}/condensed-summary")
def delete_scan_condensed_summary(scan_id: int) -> dict:
    if not clear_scan_condensed_summary(scan_id):
        raise HTTPException(status_code=404, detail=f"No scan with scan_id {scan_id}")
    return {"scan_id": scan_id, "condensed_summary": ""}


@app.post("/phase1")
def start_phase1(request: ScanRequest) -> dict:
    provider, model, api_key, api_base_url = _llm_settings(request)
    run = prescan_runs.create(
        event_id=request.event_id,
        provider=provider,
        model=model,
    )
    thread = threading.Thread(
        target=_run_phase1_background,
        args=(run, request, provider, model, api_key, api_base_url),
        daemon=True,
    )
    thread.start()
    return run.snapshot()


@app.get("/phase1/{run_id}")
def phase1_status(run_id: str) -> dict:
    run = _prescan_run(run_id)
    return run.snapshot()


@app.post("/phase2")
def start_phase2(request: PhaseTwoRequest) -> dict:
    provider, model, api_key, api_base_url = _llm_settings(request)
    analysis_types = _analysis_types(request.analysis_types)
    approval_mode = _approval_mode(request.approval_mode)
    approval_provider: Optional[str] = None
    approval_model: Optional[str] = None
    if approval_mode == APPROVAL_MODE_SMART_NON_DB:
        # Validate the smart approver's LLM settings eagerly so that a
        # misconfiguration surfaces as a 400 here instead of silently
        # disabling smart approval once the background run starts.
        approval_provider, approval_model, _, _ = _approval_llm_settings(request)
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
        approval_mode=approval_mode,
        approval_provider=approval_provider,
        approval_model=approval_model,
        escalate_smart_rejections=request.escalate_smart_rejections,
        max_reasoning_effort=request.max_reasoning_effort,
        unlimited_rounds=request.unlimited_rounds,
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
    scan_logger = _phase2_loggers.get(run_id)
    if scan_logger is not None:
        scan_logger.log_user_action("abort_requested", {"run_id": run_id})
    run.abort()
    return run.snapshot()


@app.post("/phase2/{run_id}/tool/stop")
def stop_phase2_tool(run_id: str) -> dict:
    run = _analysis_run(run_id)
    if not run.request_active_tool_stop():
        raise HTTPException(status_code=409, detail="No MCP tool is currently running")
    scan_logger = _phase2_loggers.get(run_id)
    if scan_logger is not None:
        scan_logger.log_user_action("tool_stop_requested_via_api", {"run_id": run_id})
    return run.snapshot()


@app.post("/phase2/{run_id}/tool-requests/{request_id}/decision")
def decide_phase2_tool(
    run_id: str,
    request_id: str,
    request: ToolDecisionRequest,
) -> dict:
    run = _analysis_run(run_id)
    try:
        run.decide_tool_request(request_id, request.approved, request.reason or "")
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Tool request not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    scan_logger = _phase2_loggers.get(run_id)
    if scan_logger is not None:
        scan_logger.log_user_action(
            "tool_decision",
            {
                "run_id": run_id,
                "request_id": request_id,
                "approved": request.approved,
                "reason": request.reason or "",
            },
        )
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


def _approval_mode(raw_mode: str) -> str:
    mode = (raw_mode or APPROVAL_MODE_MANUAL).strip()
    if mode not in APPROVAL_MODES:
        raise HTTPException(status_code=400, detail=f"Unsupported approval mode: {mode}")
    return mode


def _approval_llm_settings(request: PhaseTwoRequest):
    """Resolve the LLM provider/model/key used by the smart MCP approver."""
    provider = resolve_provider(request.approval_provider)
    if provider not in PROVIDERS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported smart approver provider: {provider}",
        )
    model = resolve_model(provider, request.approval_model)
    api_key = resolve_api_key(provider, None)
    if PROVIDERS[provider]["api_key_envs"] and not api_key:
        raise HTTPException(
            status_code=400,
            detail=(
                f"{PROVIDERS[provider]['label']} API key is not configured "
                "for the smart approver"
            ),
        )
    api_base_url = resolve_api_base_url(provider, None)
    return provider, model, api_key, api_base_url


def _attach_smart_approver(
    run: AnalysisRun,
    request: PhaseTwoRequest,
    scan_logger: Optional[ScanRunLogger],
) -> None:
    """Build the LLM smart approver and attach it to the run, when enabled.

    A failure here is non-fatal: the run keeps going with the smart reviewer
    disabled, so non-database tool calls fall back to manual approval.
    """
    if run.approval_mode != APPROVAL_MODE_SMART_NON_DB:
        return
    try:
        provider, model, api_key, api_base_url = _approval_llm_settings(request)
        approval_analyzer = create_analyzer(
            provider=provider,
            model=model,
            api_key=api_key,
            api_base_url=api_base_url,
        )
        approver = SmartToolApprover(
            analyzer=approval_analyzer,
            constraints=request.constraints,
            analysis_types=run.analysis_types,
            event_id=run.event_id,
            scan_logger=scan_logger,
        )
        run.attach_smart_reviewer(approver.review)
        run.add_progress(f"Smart MCP approver enabled ({provider} / {model}).")
    except Exception as exc:
        run.add_progress(
            f"Smart MCP approver unavailable ({exc}); non-database tool calls "
            "will require manual approval."
        )
        if scan_logger is not None:
            scan_logger.warning("Smart approver setup failed: %s", exc)


def _analysis_run(run_id: str) -> AnalysisRun:
    run = analysis_runs.get(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Analysis run not found")
    return run


def _prescan_run(run_id: str) -> PrescanRun:
    run = prescan_runs.get(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Pre-scan run not found")
    return run


def _run_phase1_background(
    run: PrescanRun,
    request: ScanRequest,
    provider: str,
    model: str,
    api_key: Optional[str],
    api_base_url: Optional[str],
) -> None:
    run.start()
    scan_logger = create_scan_run_logger(
        phase="phase1",
        run_id=run.run_id,
        event_id=request.event_id,
    )
    if scan_logger is not None:
        _phase1_loggers[run.run_id] = scan_logger
        scan_logger.log_input(
            "request",
            {
                "event_id": request.event_id,
                "enable_web_search": request.enable_web_search,
                "provider": provider,
                "model": model,
                "api_base_url": api_base_url,
                "has_app_details_content": request.app_details_content is not None,
                "has_user_intend_content": request.user_intend_content is not None,
            },
        )
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
            progress_callback=run.add_progress,
            scan_logger=scan_logger,
            enable_web_search=request.enable_web_search,
        )
        save_prescan(summary)
        run.complete(
            result_markdown=summary.to_markdown(),
            summary=prescan_dict(summary),
            recording_id=summary.recording_id,
        )
        if scan_logger is not None:
            scan_logger.info("Phase 1 run completed successfully.")
    except Exception as exc:
        if scan_logger is not None:
            scan_logger.error("Phase 1 run failed: %s", exc)
        run.fail(str(exc))
    finally:
        if scan_logger is not None:
            _phase1_loggers.pop(run.run_id, None)
            scan_logger.close()


def _run_phase2_background(
    run: AnalysisRun,
    request: PhaseTwoRequest,
    provider: str,
    model: str,
    api_key: Optional[str],
    api_base_url: Optional[str],
) -> None:
    run.start()
    scan_logger = create_scan_run_logger(
        phase="phase2",
        run_id=run.run_id,
        event_id=request.event_id,
    )
    if scan_logger is not None:
        _phase2_loggers[run.run_id] = scan_logger
        scan_logger.log_input(
            "request",
            {
                "event_id": request.event_id,
                "analysis_types": list(run.analysis_types),
                "constraints": request.constraints,
                "provider": provider,
                "model": model,
                "api_base_url": api_base_url,
                "approval_mode": run.approval_mode,
                "approval_provider": run.approval_provider,
                "approval_model": run.approval_model,
                "escalate_smart_rejections": run.escalate_smart_rejections,
                "prior_report_ids": list(request.prior_report_ids),
                "compact_included_reports": request.compact_included_reports,
                "max_reasoning_effort": request.max_reasoning_effort,
                "unlimited_rounds": request.unlimited_rounds,
                "has_app_details_content": request.app_details_content is not None,
                "has_user_intend_content": request.user_intend_content is not None,
            },
        )
    try:
        analyzer = create_analyzer(
            provider=provider,
            model=model,
            api_key=api_key,
            api_base_url=api_base_url,
        )
        _attach_smart_approver(run, request, scan_logger)
        prescan_summary = get_prescan(request.event_id)
        prescan_markdown = prescan_summary.to_markdown() if prescan_summary else ""
        if prescan_markdown:
            run.add_progress("Loaded stored phase-one summary.")

        prior_report_sections = _prior_report_sections(request.prior_report_ids)
        prior_reports_markdown = _join_prior_report_sections(prior_report_sections)
        if prior_reports_markdown:
            if request.compact_included_reports:
                prior_reports_markdown = _compact_prior_report_sections(
                    analyzer=analyzer,
                    sections=prior_report_sections,
                    event_id=request.event_id,
                    analysis_types=run.analysis_types,
                    constraints=request.constraints,
                    prescan_markdown=prescan_markdown,
                    provider=provider,
                    model=model,
                    api_key=api_key,
                    api_base_url=api_base_url,
                    progress_callback=run.add_progress,
                    scan_logger=scan_logger,
                )
                run.add_progress(
                    f"Loaded {len(prior_report_sections)} individually compacted "
                    "prior scan report(s) into the prompt."
                )
            else:
                run.add_progress(
                    f"Loaded {len(prior_report_sections)} prior scan report(s) into the prompt."
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
            reasoning_effort="max" if request.max_reasoning_effort else "high",
            max_rounds=None if request.unlimited_rounds else 24,
            scan_logger=scan_logger,
        )
        if run.abort_requested:
            run.complete("")
            if scan_logger is not None:
                scan_logger.info("Phase 2 run aborted before completion.")
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
        if scan_logger is not None:
            scan_logger.info(
                "Phase 2 run completed successfully (scan_id=%s).", scan_id
            )
    except Exception as exc:
        if run.abort_requested:
            run.complete("")
            if scan_logger is not None:
                scan_logger.info(
                    "Phase 2 run aborted after exception: %s", exc
                )
            return
        if scan_logger is not None:
            scan_logger.error("Phase 2 run failed: %s", exc)
        run.fail(str(exc))
    finally:
        if scan_logger is not None:
            _phase2_loggers.pop(run.run_id, None)
            scan_logger.close()


def _prior_report_sections(scan_ids: List[int]) -> list[PriorReportSection]:
    if not scan_ids:
        return []
    rows = get_phase_two_scans(scan_ids)
    rows_by_id = {int(row["scan_id"]): row for row in rows}
    sections: list[PriorReportSection] = []
    for scan_id in scan_ids:
        row = rows_by_id.get(int(scan_id))
        if row is None:
            continue
        title = row.get("scan_type_title") or "Unknown scan type"
        provider = row.get("llm_provider") or "provider"
        model = row.get("llm_model") or "model"
        body = (row.get("summary") or "").strip() or "(empty report)"
        condensed_summary = (row.get("condensed_summary") or "").strip()
        label = (
            f"Prior report #{row['scan_id']} "
            f"({title}; {provider} / {model}; event {row['event_id']})"
        )
        sections.append(
            PriorReportSection(
                scan_id=int(row["scan_id"]),
                label=label,
                markdown=f"--- {label} ---\n{body}",
                condensed_summary=condensed_summary,
            )
        )
    return sections


def _join_prior_report_sections(sections: Sequence[PriorReportSection]) -> str:
    return "\n\n".join(section.markdown for section in sections)


def _compact_prior_report_sections(
    *,
    analyzer,
    sections: Sequence[PriorReportSection],
    event_id: int,
    analysis_types: Sequence[str],
    constraints: str,
    prescan_markdown: str,
    provider: str,
    model: str,
    api_key: Optional[str],
    api_base_url: Optional[str],
    progress_callback: Callable[[str], None],
    scan_logger: Optional[ScanRunLogger],
) -> str:
    if not sections:
        return ""

    compacted_sections: list[PriorReportSection | None] = [None] * len(sections)
    sections_to_compact: list[tuple[int, PriorReportSection]] = []
    for index, section in enumerate(sections):
        if section.condensed_summary.strip():
            compacted_sections[index] = _compacted_prior_report_section(
                section,
                section.condensed_summary,
            )
        else:
            sections_to_compact.append((index, section))

    cached_count = len(sections) - len(sections_to_compact)
    if cached_count:
        progress_callback(
            f"Reused stored condensed summaries for {cached_count} prior scan report(s)."
        )

    if not sections_to_compact:
        return _join_prior_report_sections(_completed_sections(compacted_sections))

    worker_count = _prior_report_compaction_worker_count(len(sections_to_compact))
    progress_callback(
        f"Condensing {len(sections_to_compact)} prior scan report(s) in separate "
        f"LLM session(s), up to {worker_count} at a time."
    )

    if worker_count == 1:
        for index, section in sections_to_compact:
            compacted_sections[index] = _compact_prior_report_section(
                analyzer=analyzer,
                section=section,
                event_id=event_id,
                analysis_types=analysis_types,
                constraints=constraints,
                prescan_markdown=prescan_markdown,
                progress_callback=progress_callback,
                scan_logger=scan_logger,
            )
    else:
        def compact_with_new_analyzer(
            indexed_section: tuple[int, PriorReportSection],
        ) -> tuple[int, PriorReportSection]:
            index, section = indexed_section
            compacted = _compact_prior_report_section(
                analyzer=create_analyzer(
                    provider=provider,
                    model=model,
                    api_key=api_key,
                    api_base_url=api_base_url,
                ),
                section=section,
                event_id=event_id,
                analysis_types=analysis_types,
                constraints=constraints,
                prescan_markdown=prescan_markdown,
                progress_callback=progress_callback,
                scan_logger=scan_logger,
            )
            return index, compacted

        with ThreadPoolExecutor(
            max_workers=worker_count,
            thread_name_prefix="prior-report-compaction",
        ) as executor:
            for index, compacted in executor.map(
                compact_with_new_analyzer,
                sections_to_compact,
            ):
                compacted_sections[index] = compacted

    return _join_prior_report_sections(_completed_sections(compacted_sections))


def _compact_prior_report_section(
    *,
    analyzer,
    section: PriorReportSection,
    event_id: int,
    analysis_types: Sequence[str],
    constraints: str,
    prescan_markdown: str,
    progress_callback: Callable[[str], None],
    scan_logger: Optional[ScanRunLogger],
) -> PriorReportSection:
    compacted = analyzer.compact_prior_report(
        event_id=event_id,
        analysis_types=analysis_types,
        constraints=constraints,
        prescan_markdown=prescan_markdown,
        report_label=section.label,
        prior_report_markdown=section.markdown,
        on_progress=progress_callback,
        scan_logger=scan_logger,
    )
    _persist_condensed_summary(section, compacted, progress_callback)
    return _compacted_prior_report_section(section, compacted)


def _compacted_prior_report_section(
    section: PriorReportSection,
    condensed_summary: str,
) -> PriorReportSection:
    label = f"Compacted {section.label}"
    return PriorReportSection(
        scan_id=section.scan_id,
        label=label,
        markdown=f"--- {label} ---\n{condensed_summary.strip()}",
        condensed_summary=condensed_summary.strip(),
    )


def _completed_sections(
    sections: Sequence[PriorReportSection | None],
) -> list[PriorReportSection]:
    completed: list[PriorReportSection] = []
    for section in sections:
        if section is None:
            raise RuntimeError("Prior report compaction did not produce every section")
        completed.append(section)
    return completed


def _persist_condensed_summary(
    section: PriorReportSection,
    condensed_summary: str,
    progress_callback: Callable[[str], None],
) -> None:
    """Store the freshly condensed summary on the scan row it was derived from."""
    try:
        set_scan_condensed_summary(section.scan_id, condensed_summary)
        progress_callback(
            f"Stored condensed summary for prior scan report #{section.scan_id}."
        )
    except Exception as exc:
        logger.error(
            "Failed to store condensed summary for scan %d: %s", section.scan_id, exc
        )
        progress_callback(
            f"Could not store condensed summary for prior scan report "
            f"#{section.scan_id}: {exc}"
        )


def _prior_report_compaction_worker_count(report_count: int) -> int:
    if report_count <= 1:
        return max(report_count, 0)

    raw_value = os.environ.get("PHASE2_PRIOR_REPORT_COMPACTION_WORKERS", "2")
    try:
        configured_count = int(raw_value)
    except ValueError:
        configured_count = 2
    return max(1, min(report_count, configured_count))


def _prior_reports_markdown(scan_ids: List[int]) -> str:
    return _join_prior_report_sections(_prior_report_sections(scan_ids))


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
