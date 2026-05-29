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
from .jobs.store import derived_status
from .providers import list_providers
from .schemas import (
    JobStatus,
    PromptPartInfo,
    ProviderList,
    StartJobRequest,
    StartJobResponse,
    TaskTypeInfo,
    TaskTypeList,
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
    return JobStatus(
        job_id=job.job_id,
        status=derived_status(job.tasks),
        provider=job.provider,
        model=job.model,
        reasoning_effort=job.reasoning_effort,
        task_type=job.task_type,
        tasks=[
            {
                "exchange_id": task.exchange_id,
                "status": task.status,
                "result": task.result,
                "error": task.error,
                "iterations": task.iterations,
                "stopped_on_limit": task.stopped_on_limit,
            }
            for task in job.tasks
        ],
    )
