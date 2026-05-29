from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field


class RecordingInfo(BaseModel):
    """A recording plus how many packets it holds."""

    recording_id: int
    name: Optional[str] = None
    packet_count: int = 0


class NameCount(BaseModel):
    """Generic name/count pair (used for the protocol distribution)."""

    name: str
    count: int


class DirectionCounts(BaseModel):
    """Packet counts split by traffic direction."""

    incoming: int = 0
    outgoing: int = 0
    unknown: int = 0


class EntropyBucket(BaseModel):
    """One bar of the payload-entropy histogram (bits per byte, range [0, 8])."""

    bucket: int
    range_start: float
    range_end: float
    count: int


class RemoteIp(BaseModel):
    ip: str
    count: int


class EndpointNode(BaseModel):
    """A node in the remote-IP -> host -> path endpoint tree."""

    name: str
    type: str = Field(description="One of 'ip', 'host' or 'path'.")
    count: int = 0
    children: List["EndpointNode"] = Field(default_factory=list)


class RecordingStats(BaseModel):
    """Aggregated statistics across all packets of one recording."""

    recording_id: int
    packet_count: int = 0
    protocol_distribution: List[NameCount] = Field(default_factory=list)
    direction: DirectionCounts = Field(default_factory=DirectionCounts)
    entropy_histogram: List[EntropyBucket] = Field(default_factory=list)
    remote_ips: List[RemoteIp] = Field(default_factory=list)
    endpoint_tree: List[EndpointNode] = Field(default_factory=list)


# Resolve the self-referential ``children`` forward reference.
EndpointNode.model_rebuild()
