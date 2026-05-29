"""Thread-safe, in-memory store of analysis jobs and their per-exchange tasks.

The store is task-agnostic: a task's structured output is held as an opaque
``result`` dict (a serialized :class:`~app.schemas.TaskResult`). This is the only
stateful component of the backend; the narrow ``create``/``get``/``update_task``
surface is what a future persistent store would re-implement. Jobs do not survive
a process restart (acceptable for the PoC).
"""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from uuid import uuid4


@dataclass
class ExchangeTaskState:
    exchange_id: str
    status: str = "pending"  # pending | running | done | error
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    iterations: Optional[int] = None
    stopped_on_limit: Optional[bool] = None


@dataclass
class Job:
    job_id: str
    provider: str
    model: Optional[str]
    reasoning_effort: Optional[str]
    task_type: str
    tasks: List[ExchangeTaskState] = field(default_factory=list)


def derived_status(tasks: List[ExchangeTaskState]) -> str:
    """``running`` while any task is pending/running, otherwise ``done``."""
    if any(task.status in ("pending", "running") for task in tasks):
        return "running"
    return "done"


class JobStore:
    """Holds jobs in memory, guarded by a single lock."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._jobs: Dict[str, Job] = {}

    def create(
        self,
        *,
        provider: str,
        model: Optional[str],
        reasoning_effort: Optional[str],
        task_type: str,
        exchange_ids: List[str],
    ) -> str:
        job_id = uuid4().hex
        job = Job(
            job_id=job_id,
            provider=provider,
            model=model,
            reasoning_effort=reasoning_effort,
            task_type=task_type,
            tasks=[ExchangeTaskState(exchange_id=eid) for eid in exchange_ids],
        )
        with self._lock:
            self._jobs[job_id] = job
        return job_id

    def get(self, job_id: str) -> Optional[Job]:
        """Return a deep copy of the job so callers never see live mutations."""
        with self._lock:
            job = self._jobs.get(job_id)
            return copy.deepcopy(job) if job is not None else None

    def update_task(self, job_id: str, exchange_id: str, **fields: Any) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            for task in job.tasks:
                if task.exchange_id == exchange_id:
                    for key, value in fields.items():
                        setattr(task, key, value)
                    break
