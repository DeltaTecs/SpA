from __future__ import annotations

from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class ScanResultCreate(BaseModel):
    """Request body to persist a finished scan snapshot.

    ``payload`` is the opaque scanner-backend job snapshot (a ``JobStatus`` or
    ``PentestJobStatus``); the db-api stores it verbatim and never interprets it.
    """

    scan_type: str = Field(description="Producing task_type, e.g. 'vulnerability_checks', or 'pentest'.")
    created_at: Optional[int] = Field(
        default=None, description="Unix epoch milliseconds; filled by the server when omitted."
    )
    provider: Optional[str] = None
    model: Optional[str] = None
    payload: Dict[str, Any] = Field(default_factory=dict)


class ScanResultSummary(BaseModel):
    """A stored scan's metadata, without the (potentially large) payload."""

    scan_result_id: int
    recording_id: int
    scan_type: str
    created_at: int
    provider: Optional[str] = None
    model: Optional[str] = None


class ScanResultRecord(ScanResultSummary):
    """A stored scan including its full snapshot payload."""

    payload: Dict[str, Any] = Field(default_factory=dict)
