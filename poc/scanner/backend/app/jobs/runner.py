"""Concurrent execution of analysis jobs.

A job runs one analysis task over a set of exchanges, one LLM session per
exchange, on a bounded thread pool. ``McpLlmClient.run()`` is synchronous and
each MCP tool call wraps its own ``asyncio.run()``, so running it inside worker
threads is safe (each thread gets its own event loop).

The worker body (:func:`run_exchange`) is task-agnostic: it only calls the
:class:`~app.tasks.base.AnalysisTask` contract and writes opaque results to the
store, so new task types need no changes here.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor

from llm import McpLlmClient, ProviderFactory
from llm.provider.base import BaseProvider

from ..config import Settings, settings
from ..providers import validate_reasoning_effort
from ..schemas import Exchange, StartJobRequest
from ..tasks import get as get_task
from ..tasks.base import AnalysisTask
from .store import JobStore

logger = logging.getLogger(__name__)

#: Shared, process-wide job store and worker pool.
store = JobStore()
_executor = ThreadPoolExecutor(
    max_workers=max(1, settings.max_concurrency), thread_name_prefix="plan-worker"
)


def build_provider(request: StartJobRequest, cfg: Settings) -> BaseProvider:
    """Create the LLM provider for a job (raises ValueError if a key is missing)."""
    api_key = cfg.api_key_for(request.provider)
    validate_reasoning_effort(request.provider, request.reasoning_effort)
    return ProviderFactory.create(
        request.provider,
        api_key=api_key,
        model=request.model,
        reasoning_effort=request.reasoning_effort,
        timeout=cfg.llm_timeout,
    )


def submit_job(request: StartJobRequest, cfg: Settings = settings) -> str:
    """Validate the request, create the job, and submit one worker per exchange.

    Raises ``KeyError`` for an unknown task type and ``ValueError`` for an invalid
    provider / missing API key — both surfaced as HTTP 400 by the caller.
    """
    task = get_task(request.task_type)
    provider = build_provider(request, cfg)
    # Warm the lazily-built SDK client once here so the worker threads share a
    # single client instead of racing to build their own on first use.
    getattr(provider, "client", None)

    job_id = store.create(
        provider=request.provider,
        model=provider.model,
        reasoning_effort=provider.reasoning_effort,
        task_type=request.task_type,
        exchange_ids=[exchange.id for exchange in request.exchanges],
    )
    logger.info(
        "Job %s: %d exchange(s), task=%s, provider=%s, model=%s, reasoning_effort=%s",
        job_id,
        len(request.exchanges),
        request.task_type,
        provider.name,
        provider.model,
        provider.reasoning_effort or "<default>",
    )
    for exchange in request.exchanges:
        _executor.submit(
            run_exchange, job_id, exchange, task, provider, request.max_iterations, cfg
        )
    return job_id


def run_exchange(
    job_id: str,
    exchange: Exchange,
    task: AnalysisTask,
    provider: BaseProvider,
    max_iterations: int,
    cfg: Settings,
) -> None:
    """Run one analysis task against one exchange and record the outcome."""
    store.update_task(job_id, exchange.id, status="running")
    try:
        toolsets = task.select_toolsets(cfg)
        client = McpLlmClient(provider, toolsets, max_iterations=max_iterations)
        run_result = client.run(
            task.build_user_prompt(exchange), system=task.build_system_prompt()
        )
        result = task.parse_output(run_result.output)
        store.update_task(
            job_id,
            exchange.id,
            status="done",
            result=result.model_dump(),
            iterations=run_result.iterations,
            stopped_on_limit=run_result.stopped_on_limit,
        )
    except Exception as exc:  # noqa: BLE001 - record the failure on the task
        logger.exception("Analysis failed for exchange %s in job %s", exchange.id, job_id)
        store.update_task(job_id, exchange.id, status="error", error=str(exc))
