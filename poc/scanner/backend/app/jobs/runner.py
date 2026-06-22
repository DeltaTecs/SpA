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
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from concurrent.futures import wait as futures_wait
from typing import List

from llm import McpLlmClient, OperationCancelled, ProviderFactory
from llm.provider.base import BaseProvider

from ..activity import THINKING, SessionActivity
from ..config import Settings, settings
from ..persistence import persist_scan
from ..providers import validate_reasoning_effort
from ..schemas import Exchange, StartJobRequest
from ..tasks import get as get_task
from ..tasks.base import AnalysisTask, PromptOverrideMap
from .serialization import build_job_status
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
    prompt_overrides = task.normalize_prompt_overrides(request.prompt_overrides)
    provider = build_provider(request, cfg)
    # Warm the lazily-built SDK client once here so the worker threads share a
    # single client instead of racing to build their own on first use.
    getattr(provider, "client", None)

    job_id = store.create(
        recording_id=request.recording_id,
        provider=request.provider,
        model=provider.model,
        reasoning_effort=provider.reasoning_effort,
        task_type=request.task_type,
        exchange_ids=[exchange.id for exchange in request.exchanges],
        call_budget=cfg.tavily_call_budget_per_job,
    )
    logger.info(
        "Job %s: recording=%s, %d exchange(s), task=%s, provider=%s, model=%s, reasoning_effort=%s",
        job_id,
        request.recording_id,
        len(request.exchanges),
        request.task_type,
        provider.name,
        provider.model,
        provider.reasoning_effort or "<default>",
    )
    futures = [
        _executor.submit(
            run_exchange,
            job_id,
            exchange,
            task,
            provider,
            request.max_iterations,
            cfg,
            prompt_overrides,
        )
        for exchange in request.exchanges
    ]
    _persist_on_completion(job_id, request.recording_id, futures, cfg)
    return job_id


def _persist_on_completion(
    job_id: str, recording_id: int, futures: List[Future], cfg: Settings
) -> None:
    """Wait (off the request path) for all workers, then persist the final snapshot."""

    def wait_and_persist() -> None:
        futures_wait(futures)
        job = store.get(job_id)
        if job is None:
            return
        status = build_job_status(job)
        persist_scan(
            cfg,
            recording_id=recording_id,
            scan_type=status.task_type,
            provider=status.provider,
            model=status.model,
            payload=status.model_dump(mode="json"),
        )

    threading.Thread(
        target=wait_and_persist, name=f"plan-persist-{job_id[:8]}", daemon=True
    ).start()


def run_exchange(
    job_id: str,
    exchange: Exchange,
    task: AnalysisTask,
    provider: BaseProvider,
    max_iterations: int,
    cfg: Settings,
    prompt_overrides: PromptOverrideMap | None = None,
) -> None:
    """Run one analysis task against one exchange and record the outcome."""
    token = store.token_for(job_id)
    if token is not None and token.is_cancelled:
        return  # job was terminated before this worker started; leave it cancelled
    store.update_task(job_id, exchange.id, status="running", activity=THINKING)
    activity = SessionActivity(
        lambda phrase: store.update_task(job_id, exchange.id, activity=phrase)
    )
    try:
        toolsets = task.select_toolsets(cfg, budget=store.budget_for(job_id))
        client = McpLlmClient(
            provider, toolsets, max_iterations=max_iterations, cancel_token=token, activity=activity
        )
        system_prompt = task.build_system_prompt_for_run(prompt_overrides)
        user_prompt = task.build_user_prompt_for_run(exchange, prompt_overrides)
        run_result = client.run(user_prompt, system=system_prompt)
        result = task.parse_output(run_result.output)
        store.update_task(
            job_id,
            exchange.id,
            status="done",
            result=result.model_dump(),
            iterations=run_result.iterations,
            stopped_on_limit=run_result.stopped_on_limit,
            activity=None,
        )
    except OperationCancelled:
        # The store already marked this task cancelled (and froze it); nothing to record.
        logger.info("Analysis cancelled for exchange %s in job %s", exchange.id, job_id)
    except Exception as exc:  # noqa: BLE001 - record the failure on the task
        logger.exception("Analysis failed for exchange %s in job %s", exchange.id, job_id)
        store.update_task(job_id, exchange.id, status="error", error=str(exc), activity=None)
