from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class TranscriptCreate(BaseModel):
    """One item's tool-use transcript, persisted alongside its scan snapshot.

    ``steps`` is the opaque, ordered transcript produced by the scanner-backend
    (reasoning + tool calls with arguments/output and the reviewer's decision);
    the db-api stores it verbatim and never interprets it.
    """

    item_id: str = Field(description="Item this transcript belongs to (PentestItemStatus.item_id).")
    steps: List[Dict[str, Any]] = Field(default_factory=list)


class ScanResultCreate(BaseModel):
    """Request body to persist a finished scan snapshot.

    ``payload`` is the opaque scanner-backend job snapshot (a ``JobStatus`` or
    ``PentestJobStatus``); the db-api stores it verbatim and never interprets it.
    ``transcripts`` (optional) are the per-item tool-use transcripts, stored in a
    side table linked to the new scan_result in the same transaction.
    """

    scan_type: str = Field(description="Producing task_type, e.g. 'vulnerability_checks', or 'pentest'.")
    created_at: Optional[int] = Field(
        default=None, description="Unix epoch milliseconds; filled by the server when omitted."
    )
    provider: Optional[str] = None
    model: Optional[str] = None
    payload: Dict[str, Any] = Field(default_factory=dict)
    transcripts: List[TranscriptCreate] = Field(default_factory=list)


class TranscriptRecord(BaseModel):
    """A stored tool-use transcript for one item of a scan_result."""

    item_id: str
    steps: List[Dict[str, Any]] = Field(default_factory=list)


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
