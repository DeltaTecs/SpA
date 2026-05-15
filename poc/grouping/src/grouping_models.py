"""Small result model kept for callers that import this module."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class PacketPurposeResult:
    """A concise purpose note produced for one packet."""

    packet_id: int
    text: str
