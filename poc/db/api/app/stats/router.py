from __future__ import annotations

from typing import List

from fastapi import APIRouter, Query

from .repository import StatsRepository
from .schemas import RecordingInfo, RecordingStats

router = APIRouter(tags=["stats"])
repository = StatsRepository()


@router.get("/recordings", response_model=List[RecordingInfo])
def list_recordings() -> List[RecordingInfo]:
    """List all recordings with their packet counts."""
    return repository.list_recordings()


@router.get("/stats/{recording_id}", response_model=RecordingStats)
def recording_stats(
    recording_id: int,
    top_ips: int = Query(50, ge=1, le=500, description="Max remote IPs to return."),
) -> RecordingStats:
    """Aggregated dashboard statistics for one recording.

    Returns zero-filled stats for an unknown/empty recording rather than 404, so
    the dashboard renders cleanly before any data is ingested.
    """
    return repository.recording_stats(recording_id, top_ips=top_ips)
