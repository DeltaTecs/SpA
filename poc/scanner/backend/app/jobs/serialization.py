"""Map the in-memory :class:`Job` to the wire :class:`JobStatus`.

Kept in one place so the ``GET /jobs/{id}`` response and the snapshot persisted
on completion are byte-identical.
"""

from __future__ import annotations

from ..schemas import JobStatus
from .store import Job, derived_status


def build_job_status(job: Job) -> JobStatus:
    """Serialize a job snapshot into its public ``JobStatus``."""
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
                "activity": task.activity,
            }
            for task in job.tasks
        ],
    )
