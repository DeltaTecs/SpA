"""Data models passed between grouping orchestration and LLM analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PacketFact:
    """Cached packet metadata parsed from the MCP packet_info text."""

    packet_id: int
    timestamp: int
    offset_ms: int
    conversation_id: Optional[int]
    app_protocol: str
    payload_length: int
    has_http: bool
    text: str

    @property
    def is_groupable(self) -> bool:
        """Packets without payload or HTTP headers do not drive event grouping."""
        return self.payload_length > 0 or self.has_http


@dataclass
class ContextSummary:
    """LLM-generated pass-1 summary for a conversation, stream, or time window."""

    summary_id: str
    kind: str
    label: str
    packet_ids: List[int]
    text: str

    def compact(self, max_chars: int = 1200) -> str:
        """Render a prompt-sized form for later candidate and assignment passes."""
        body = self.text.strip()
        if len(body) > max_chars:
            body = body[: max_chars - 3].rstrip() + "..."
        packets = ", ".join(str(packet_id) for packet_id in self.packet_ids[:20])
        if len(self.packet_ids) > 20:
            packets += ", ..."
        return (
            f"{self.summary_id} [{self.kind}] {self.label}\n"
            f"packets: {packets if packets else '(none)'}\n"
            f"{body}"
        )


@dataclass
class EventCandidate:
    """Pass-2 event proposal used as a non-persisted assignment target."""

    candidate_id: str
    description: str
    source_summary_ids: List[str] = field(default_factory=list)
    packet_ids: List[int] = field(default_factory=list)
    rationale: str = ""

    def compact(self) -> str:
        """Render the candidate in a stable format for assignment prompts."""
        source_text = ", ".join(self.source_summary_ids) or "unknown"
        packet_text = ", ".join(str(packet_id) for packet_id in self.packet_ids[:20])
        if len(self.packet_ids) > 20:
            packet_text += ", ..."
        return (
            f"{self.candidate_id}: {self.description}\n"
            f"sources: {source_text}\n"
            f"packets: {packet_text if packet_text else '(not specified)'}\n"
            f"rationale: {self.rationale or '(none)'}"
        )


@dataclass
class PacketDecision:
    """Validated shape expected from the LLM before any DB write happens."""

    packet_id: int
    event_id: Optional[int]
    new_event: Optional[str]
    confidence: float
    rationale: str

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "PacketDecision":
        """Normalize model JSON into the strict decision object used downstream."""
        packet_id = int(raw.get("packet_id"))

        event_id_raw = raw.get("event_id")
        event_id: Optional[int]
        if event_id_raw in (None, "", "null"):
            event_id = None
        else:
            event_id = int(event_id_raw)

        new_event_raw = raw.get("new_event")
        if isinstance(new_event_raw, dict):
            new_event = (
                new_event_raw.get("description")
                or new_event_raw.get("candidate_id")
                or new_event_raw.get("name")
            )
        elif new_event_raw in (None, "", "null"):
            new_event = None
        else:
            new_event = str(new_event_raw)

        confidence_raw = raw.get("confidence", 0)
        try:
            confidence = float(confidence_raw)
        except (TypeError, ValueError):
            confidence = 0.0
        confidence = max(0.0, min(confidence, 1.0))

        rationale = str(raw.get("rationale") or "").strip()

        return cls(
            packet_id=packet_id,
            event_id=event_id,
            new_event=new_event.strip() if new_event else None,
            confidence=confidence,
            rationale=rationale,
        )
