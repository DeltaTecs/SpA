"""Pydantic request/response models for the scanner backend HTTP surface.

These are intentionally self-contained (the backend shares no code with the
db-api): ``Exchange`` mirrors the db-api shape, since the frontend fetches
exchanges from the db-api and posts the selected/edited ones here.
"""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


# --- exchanges (mirrors the db-api exchanges schema) -------------------------


class Endpoint(BaseModel):
    ip: Optional[str] = None
    port: Optional[int] = None


class HttpExchangeInfo(BaseModel):
    method: Optional[str] = None
    path: Optional[str] = None
    endpoint_path: Optional[str] = None
    param_names: List[str] = Field(default_factory=list)
    status_code: Optional[int] = None
    host: Optional[str] = None


class Exchange(BaseModel):
    """One data exchange to analyse. Only ``id`` is required; the rest is the
    (possibly user-edited) detail the frontend fetched from the db-api."""

    id: str
    kind: Literal["conversation", "http_pair"] = "conversation"
    transport: Optional[str] = None
    local: Optional[Endpoint] = None
    remote: Optional[Endpoint] = None
    representative_packet_ids: List[int] = Field(default_factory=list)
    packet_count: int = 0
    payload_bytes: int = 0
    protocols: List[str] = Field(default_factory=list)
    http: Optional[HttpExchangeInfo] = None
    dedup_key: Optional[str] = None


# --- providers & tasks -------------------------------------------------------


class ProviderOption(BaseModel):
    type: str
    requires_key: bool
    default_model: Optional[str] = None
    model_options: List[str] = Field(default_factory=list)


class ProviderList(BaseModel):
    providers: List[ProviderOption]


class TaskTypeInfo(BaseModel):
    task_type: str
    title: str
    description: str
    result_version: int


class TaskTypeList(BaseModel):
    tasks: List[TaskTypeInfo]


# --- jobs --------------------------------------------------------------------


class StartJobRequest(BaseModel):
    recording_id: int
    provider: str
    model: Optional[str] = None
    task_type: str = "vulnerability_checks"
    max_iterations: int = Field(10, ge=1, le=50)
    exchanges: List[Exchange] = Field(default_factory=list)


class StartJobResponse(BaseModel):
    job_id: str


class TaskResult(BaseModel):
    """Generic, versioned envelope for any analysis task's structured output.

    ``payload`` is task-specific (for ``vulnerability_checks`` it is
    ``{"checks": [...]}``). The job/store/transport never inspect it, so new task
    types can ship their own payload shape and frontend renderer.
    """

    task_type: str
    result_version: int
    payload: Dict[str, Any] = Field(default_factory=dict)


class VulnerabilityCheck(BaseModel):
    """One suggested vulnerability check (the ``vulnerability_checks`` payload)."""

    title: str = "(untitled)"
    description: str = ""
    rationale: str = ""
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    technique: Optional[str] = None
    references: List[str] = Field(default_factory=list)


class ExchangeTaskStatus(BaseModel):
    exchange_id: str
    status: Literal["pending", "running", "done", "error"]
    result: Optional[TaskResult] = None
    error: Optional[str] = None
    iterations: Optional[int] = None
    stopped_on_limit: Optional[bool] = None


class JobStatus(BaseModel):
    job_id: str
    status: Literal["running", "done", "error"]
    provider: str
    model: Optional[str] = None
    task_type: str
    tasks: List[ExchangeTaskStatus] = Field(default_factory=list)
