from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional


@dataclass
class EventPacket:
    packet_id: int
    recording_id: int
    number: Optional[int]
    timestamp: Optional[int]
    conversation_id: Optional[int]


@dataclass
class EventContext:
    event_id: int
    description: str
    start_timestamp: Optional[int]
    end_timestamp: Optional[int]
    packets: List[EventPacket] = field(default_factory=list)

    @property
    def packet_ids(self) -> List[int]:
        return [packet.packet_id for packet in self.packets]

    @property
    def recording_ids(self) -> List[int]:
        return sorted({packet.recording_id for packet in self.packets})

    @property
    def primary_recording_id(self) -> Optional[int]:
        return self.recording_ids[0] if self.recording_ids else None


@dataclass
class PacketFact:
    packet_id: int
    timestamp: Optional[int]
    offset_ms: Optional[int]
    conversation_id: Optional[int]
    text: str


@dataclass
class ScanSummary:
    event_id: int
    recording_id: Optional[int]
    most_interesting_packet_id: Optional[int]
    packet_content: str
    event_summary: str
    suspected_trigger: str
    entrypoint_rationale: str
    supporting_packet_ids: List[int] = field(default_factory=list)
    phase_two_todo: str = "Phase two is intentionally not implemented yet."

    @classmethod
    def from_dict(
        cls,
        raw: dict[str, Any],
        *,
        event_id: int,
        recording_id: Optional[int],
    ) -> "ScanSummary":
        return cls(
            event_id=int(raw.get("event_id") or event_id),
            recording_id=_optional_int(raw.get("recording_id"), recording_id),
            most_interesting_packet_id=_optional_int(
                raw.get("most_interesting_packet_id")
                or raw.get("interesting_packet_id")
                or raw.get("packet_id"),
                None,
            ),
            packet_content=str(raw.get("packet_content") or "").strip(),
            event_summary=str(raw.get("event_summary") or raw.get("summary") or "").strip(),
            suspected_trigger=str(
                raw.get("suspected_trigger")
                or raw.get("why_event_happened")
                or raw.get("user_action")
                or ""
            ).strip(),
            entrypoint_rationale=str(
                raw.get("entrypoint_rationale") or raw.get("rationale") or ""
            ).strip(),
            supporting_packet_ids=_int_list(
                raw.get("supporting_packet_ids") or raw.get("supporting_packets") or []
            ),
            phase_two_todo=str(
                raw.get("phase_two_todo")
                or "Phase two is intentionally not implemented yet."
            ).strip(),
        )

    def to_markdown(self) -> str:
        packet_id = (
            str(self.most_interesting_packet_id)
            if self.most_interesting_packet_id is not None
            else "(not selected)"
        )
        recording_id = str(self.recording_id) if self.recording_id is not None else "(unknown)"
        supporting = ", ".join(str(pid) for pid in self.supporting_packet_ids) or "(none)"
        return "\n".join(
            [
                f"# Vulnerability Scan Phase 1 Summary - Event {self.event_id}",
                "",
                f"- Recording ID: {recording_id}",
                f"- Most interesting packet ID: {packet_id}",
                f"- Supporting packet IDs: {supporting}",
                "",
                "## Packet Content",
                self.packet_content or "(not provided)",
                "",
                "## Event Summary",
                self.event_summary or "(not provided)",
                "",
                "## Suspected Trigger",
                self.suspected_trigger or "(not provided)",
                "",
                "## Entrypoint Rationale",
                self.entrypoint_rationale or "(not provided)",
                "",
                "## Phase 2",
                self.phase_two_todo or "Phase two is intentionally not implemented yet.",
            ]
        )


def _optional_int(value: Any, default: Optional[int]) -> Optional[int]:
    if value in (None, "", "null", "None"):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _int_list(raw: Any) -> List[int]:
    if not isinstance(raw, list):
        return []
    values: List[int] = []
    for item in raw:
        try:
            values.append(int(item))
        except (TypeError, ValueError):
            continue
    return values
