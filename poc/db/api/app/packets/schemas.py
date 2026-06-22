from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field


class IpHeader(BaseModel):
    src_addr: Optional[str] = None
    dst_addr: Optional[str] = None


class PortHeader(BaseModel):
    """Shared shape for the TCP and UDP header rows."""

    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    length: Optional[int] = None


class HttpHeader(BaseModel):
    header_information_id: int
    text_header: Optional[str] = None
    stream_id: Optional[int] = None
    version: Optional[int] = None


class PacketHeaders(BaseModel):
    ip: Optional[IpHeader] = None
    tcp: Optional[PortHeader] = None
    udp: Optional[PortHeader] = None
    http: List[HttpHeader] = Field(default_factory=list)


class HttpSummary(BaseModel):
    """Condensed HTTP info derived from the first HTTP header of a packet."""

    method: Optional[str] = None
    host: Optional[str] = None
    path: Optional[str] = None
    status_code: Optional[int] = None
    status_text: Optional[str] = None
    stream_id: Optional[int] = None


class PacketSummary(BaseModel):
    """Lightweight packet view returned by list queries.

    Beyond the raw packet columns, list queries also populate the
    ``remote_ip``/``remote_port``/``local_port``, ``http`` summary and
    ``association_key`` fields by joining the related header rows. These stay
    optional so the single-packet detail view (which carries full ``headers``)
    can reuse the same model without recomputing them.
    """

    packet_id: int
    recording_id: Optional[int] = None
    conversation_id: Optional[int] = None
    from_local: Optional[bool] = None
    timestamp: Optional[int] = None
    number: Optional[int] = None
    protocols: List[str] = Field(
        default_factory=list,
        description="Ordered protocol stack, outermost first (e.g. IP > TCP > HTTP).",
    )
    entropy: Optional[float] = None
    payload_length: int = Field(
        0, description="Byte length of the decrypted application payload."
    )
    remote_ip: Optional[str] = Field(
        None, description="Peer IP (dst when outbound, src when inbound)."
    )
    remote_port: Optional[int] = None
    local_port: Optional[int] = None
    http: Optional[HttpSummary] = None
    association_key: Optional[str] = Field(
        None,
        description=(
            "Stable grouping key for the explorer color toggle: the normalized "
            "TCP/UDP 5-tuple, further split per HTTP stream when present."
        ),
    )


class PacketDetail(PacketSummary):
    """Full packet view including parsed per-protocol headers."""

    headers: PacketHeaders = Field(default_factory=PacketHeaders)


class PacketPage(BaseModel):
    """A page of packet summaries plus the total matching the filters."""

    items: List[PacketSummary]
    total: int
    limit: int
    offset: int


class PacketPayload(BaseModel):
    """Raw packet bytes, base64-encoded so they survive JSON transport."""

    packet_id: int
    encoding: str = "base64"
    clear_application_payload: Optional[str] = None
    clear_application_payload_length: int = 0
    packet_bytes: Optional[str] = None
    packet_bytes_length: int = 0
