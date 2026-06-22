from __future__ import annotations

from fastapi import APIRouter

from .repository import ExchangeRepository
from .schemas import ExchangeList

router = APIRouter(tags=["exchanges"])
repository = ExchangeRepository()


@router.get("/recordings/{recording_id}/exchanges", response_model=ExchangeList)
def list_exchanges(recording_id: int) -> ExchangeList:
    """Compile the interesting data exchanges for one recording.

    Returns conversation flows (clear payload, no HTTP) and deduplicated HTTP
    request/response pairs. Returns an empty list for an unknown/empty recording
    rather than 404, mirroring the stats endpoint.
    """
    items = repository.list_exchanges(recording_id)
    return ExchangeList(recording_id=recording_id, items=items)
