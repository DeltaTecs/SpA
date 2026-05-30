from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query

from .repository import ScanRepository
from .schemas import ScanResultCreate, ScanResultRecord, ScanResultSummary

router = APIRouter(tags=["scans"])
repository = ScanRepository()


@router.post(
    "/recordings/{recording_id}/scans",
    response_model=ScanResultRecord,
    status_code=201,
)
def create_scan(recording_id: int, body: ScanResultCreate) -> ScanResultRecord:
    """Persist a finished scan snapshot, pruning history beyond the per-type cap."""
    return repository.create(recording_id, body)


@router.get(
    "/recordings/{recording_id}/scans/latest",
    response_model=ScanResultRecord,
)
def latest_scan(
    recording_id: int,
    scan_type: str = Query(..., description="e.g. 'vulnerability_checks' or 'pentest'."),
) -> ScanResultRecord:
    """Return the most recent stored scan of a type for a recording (404 if none)."""
    record = repository.latest(recording_id, scan_type)
    if record is None:
        raise HTTPException(
            status_code=404,
            detail=f"No stored '{scan_type}' scan for recording {recording_id}.",
        )
    return record


@router.get(
    "/recordings/{recording_id}/scans",
    response_model=List[ScanResultSummary],
)
def list_scans(
    recording_id: int,
    scan_type: Optional[str] = Query(None, description="Optional filter by scan type."),
) -> List[ScanResultSummary]:
    """List stored scan snapshots (metadata only) for a recording, newest first."""
    return repository.list(recording_id, scan_type)


@router.get("/scans/{scan_result_id}", response_model=ScanResultRecord)
def get_scan(scan_result_id: int) -> ScanResultRecord:
    """Return a single stored scan snapshot, including its payload (404 if unknown)."""
    record = repository.get(scan_result_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Unknown scan result '{scan_result_id}'.")
    return record


@router.delete("/scans/{scan_result_id}")
def delete_scan(scan_result_id: int) -> dict[str, bool]:
    """Delete a single stored scan snapshot (404 if unknown)."""
    if not repository.delete(scan_result_id):
        raise HTTPException(status_code=404, detail=f"Unknown scan result '{scan_result_id}'.")
    return {"deleted": True}
