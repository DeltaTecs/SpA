"""Scanner backend: HTTP surface over the ``llm`` package.

Exposes the LLM analysis-planning feature for the frontend's "Create Plan" tab:
list providers and analysis task types, start a concurrent analysis job over a
set of data exchanges, and poll its per-exchange results. All packet/web access
happens via MCP tools inside the ``llm`` package; this service holds no DB logic.
"""

from __future__ import annotations

import logging
import time

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

from llm import configure_logging

from .config import settings
from .jobs.runner import store, submit_job
from .jobs.serialization import build_job_status
from .mcp_catalog import (
    build_catalog,
    list_selectable_tool_specs,
    terminate_tool_processes,
)
from .pentest import store as pentest_store
from .pentest import submit_pentest_job
from .pentest.serialization import build_pentest_status
from .providers import list_providers
from .schemas import (
    JobStatus,
    McpToolInfo,
    McpToolsetInfo,
    McpToolsResponse,
    PentestJobStatus,
    PromptPartInfo,
    ProviderList,
    ReviewDecisionRequest,
    StartJobRequest,
    StartJobResponse,
    StartPentestJobRequest,
    StartPentestJobResponse,
    TaskTypeInfo,
    TaskTypeList,
    TerminationResult,
    ToolTerminationInfo,
)
from .tasks import available as available_tasks

_log_file = configure_logging()
logger = logging.getLogger(__name__)
logger.info(
    "Starting scanner backend (mcp_packet_db_url=%s, web_search=%s, max_concurrency=%d, logs=%s)",
    settings.mcp_packet_db_url,
    "tavily" if settings.tavily_url else "disabled",
    settings.max_concurrency,
    _log_file,
)

app = FastAPI(title="Scanner Backend", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    elapsed_ms = (time.perf_counter() - start) * 1000
    logger.info(
        "%s %s -> %s (%.1f ms)",
        request.method,
        request.url.path,
        response.status_code,
        elapsed_ms,
    )
    return response


@app.get("/health", tags=["health"])
def health() -> dict:
    return {"status": "ok"}


@app.get("/providers", response_model=ProviderList, tags=["plan"])
def get_providers() -> ProviderList:
    """List the selectable LLM providers and their model options."""
    return ProviderList(providers=list_providers())


@app.get("/tasks", response_model=TaskTypeList, tags=["plan"])
def get_tasks() -> TaskTypeList:
    """List the registered analysis task types (drives the UI task picker)."""
    return TaskTypeList(
        tasks=[
            TaskTypeInfo(
                task_type=task.task_type,
                title=task.title,
                description=task.description,
                result_version=task.result_version,
                prompt_parts=[
                    PromptPartInfo(
                        id=part.id,
                        title=part.title,
                        scope=part.scope,
                        content=part.content,
                        description=part.description,
                    )
                    for part in task.prompt_parts()
                ],
            )
            for task in available_tasks()
        ]
    )


@app.post("/jobs", response_model=StartJobResponse, status_code=202, tags=["plan"])
def start_job(request: StartJobRequest) -> StartJobResponse:
    """Start a concurrent analysis job over the selected exchanges."""
    try:
        job_id = submit_job(request, settings)
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return StartJobResponse(job_id=job_id)


@app.get("/jobs/{job_id}", response_model=JobStatus, tags=["plan"])
def get_job(job_id: str) -> JobStatus:
    """Return a job's status and per-exchange results (poll until ``done``)."""
    job = store.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Unknown job '{job_id}'.")
    return build_job_status(job)


@app.post("/jobs/{job_id}/cancel", response_model=TerminationResult, tags=["plan"])
def cancel_job(job_id: str) -> TerminationResult:
    """Terminate an analysis job and kill all MCP tools and their tool processes."""
    if not store.cancel(job_id):
        raise HTTPException(status_code=404, detail=f"Unknown job '{job_id}'.")
    return _terminate_tools(job_id)


def _terminate_tools(job_id: str) -> TerminationResult:
    """Kill every stop-capable MCP server's tool processes and report the outcome.

    Run after the job's cancellation token is set, so its sessions stop as soon
    as their in-flight (now-killed) tool calls return.
    """
    tools = [
        ToolTerminationInfo(name=t.name, category=t.category, ok=t.ok, detail=t.detail)
        for t in terminate_tool_processes(settings)
    ]
    return TerminationResult(job_id=job_id, cancelled=True, tools=tools)


# --- pentest -----------------------------------------------------------------


@app.get("/pentest/tools", response_model=McpToolsResponse, tags=["pentest"])
def get_pentest_tools() -> McpToolsResponse:
    """List the MCP tools available to expose to the pentest model, by toolset.

    A toolset that cannot be reached is returned with an empty tool list (logged)
    so the UI degrades gracefully instead of failing entirely.
    """
    toolsets = []
    for entry in build_catalog(settings):
        try:
            specs = list_selectable_tool_specs(entry)
            tools = [McpToolInfo(name=spec.name, description=spec.description) for spec in specs]
        except Exception as exc:  # noqa: BLE001 - one unreachable server must not 500
            logger.warning("Could not list tools for toolset '%s': %s", entry.name, exc)
            tools = []
        toolsets.append(McpToolsetInfo(name=entry.name, category=entry.category, tools=tools))
    return McpToolsResponse(toolsets=toolsets)


@app.post(
    "/pentest/jobs",
    response_model=StartPentestJobResponse,
    status_code=202,
    tags=["pentest"],
)
def start_pentest_job(request: StartPentestJobRequest) -> StartPentestJobResponse:
    """Start one investigation session per plan item (the pentest job)."""
    try:
        job_id = submit_pentest_job(request, settings)
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return StartPentestJobResponse(job_id=job_id)


@app.get("/pentest/jobs/{job_id}", response_model=PentestJobStatus, tags=["pentest"])
def get_pentest_job(job_id: str) -> PentestJobStatus:
    """Return a pentest job's status, per-item reports, and pending tool reviews."""
    job = pentest_store.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Unknown pentest job '{job_id}'.")
    return build_pentest_status(job)


@app.post("/pentest/jobs/{job_id}/reviews/{review_id}", tags=["pentest"])
def resolve_pentest_review(
    job_id: str, review_id: str, decision: ReviewDecisionRequest
) -> dict:
    """Approve or deny a pending tool call, unblocking its session."""
    resolved = pentest_store.resolve_review(
        job_id, review_id, decision.approved, decision.hint
    )
    if not resolved:
        raise HTTPException(status_code=404, detail="Unknown or already-resolved review.")
    return {"resolved": True}


@app.post("/pentest/jobs/{job_id}/cancel", response_model=TerminationResult, tags=["pentest"])
def cancel_pentest_job(job_id: str) -> TerminationResult:
    """Terminate a pentest job and kill all MCP tools and their tool processes.

    Also releases any sessions blocked awaiting a manual tool review.
    """
    if not pentest_store.cancel(job_id):
        raise HTTPException(status_code=404, detail=f"Unknown pentest job '{job_id}'.")
    return _terminate_tools(job_id)
