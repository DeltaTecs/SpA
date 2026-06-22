from __future__ import annotations

from typing import Literal, Optional

from fastapi import APIRouter, HTTPException, Query

from .repository import PacketFilters, PacketRepository
from .schemas import PacketDetail, PacketPage, PacketPayload


router = APIRouter(prefix="/packets", tags=["packets"])
repository = PacketRepository()
ApplicationProtocolFilter = Literal["http", "websocket", "other"]


@router.get("", response_model=PacketPage)
def list_packets(
    recording_id: Optional[int] = Query(None, description="Limit to one recording."),
    conversation_id: Optional[int] = Query(
        None, description="Limit to one conversation."
    ),
    from_local: Optional[bool] = Query(
        None, description="Filter by traffic direction (true = outbound)."
    ),
    protocol: Optional[str] = Query(
        None, description="Only packets whose stack contains this protocol name."
    ),
    has_clear_payload: Optional[bool] = Query(
        None,
        description="Filter by decrypted application payload presence.",
    ),
    has_http_header_text: Optional[bool] = Query(
        None,
        description="Filter by non-empty stored HTTP header text presence.",
    ),
    app_protocol: Optional[ApplicationProtocolFilter] = Query(
        None,
        description="Application protocol bucket: http, websocket, or other.",
    ),
    start_ms: Optional[int] = Query(
        None, description="Only packets at/after this epoch-millisecond timestamp."
    ),
    end_ms: Optional[int] = Query(
        None, description="Only packets at/before this epoch-millisecond timestamp."
    ),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> PacketPage:
    """List packets matching the given filters, ordered by time then number."""
    filters = PacketFilters(
        recording_id=recording_id,
        conversation_id=conversation_id,
        from_local=from_local,
        protocol=protocol,
        has_clear_payload=has_clear_payload,
        has_http_header_text=has_http_header_text,
        app_protocol=app_protocol,
        start_ms=start_ms,
        end_ms=end_ms,
        limit=limit,
        offset=offset,
    )
    items, total = repository.list_packets(filters)
    return PacketPage(items=items, total=total, limit=limit, offset=offset)


@router.get("/{packet_id}", response_model=PacketDetail)
def get_packet(packet_id: int) -> PacketDetail:
    """Fetch a single packet with its parsed protocol headers."""
    packet = repository.get_packet(packet_id)
    if packet is None:
        raise HTTPException(status_code=404, detail=f"packet_id {packet_id} not found")
    return packet


@router.get("/{packet_id}/payload", response_model=PacketPayload)
def get_packet_payload(packet_id: int) -> PacketPayload:
    """Fetch a packet's raw bytes (base64-encoded)."""
    payload = repository.get_payload(packet_id)
    if payload is None:
        raise HTTPException(status_code=404, detail=f"packet_id {packet_id} not found")
    return payload
