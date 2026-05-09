"""Orchestrate multi-pass packet grouping and own all DB mutations."""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from grouping_models import ContextSummary, EventCandidate, PacketDecision, PacketFact
from llm_analyzer import PacketAnalyzer
from mcp_client import MCPClient
from packet_tools import build_langchain_tools
from user_context import UserAction, format_user_context


logger = logging.getLogger(__name__)

# Maximum packet-info records included in any single pass-1 summary prompt.
MAX_CONTEXT_PACKETS = 100

# Maximum number of time-window summaries to generate for one recording.
MAX_TIME_WINDOW_SUMMARIES = 20

# Default duration for automatic time windows when no user actions are supplied.
TIME_WINDOW_MS = 5_000

# Maximum groupable packets per automatic time window, independent of duration.
TIME_WINDOW_PACKET_LIMIT = 50

# HTTP stream IDs are sparsely populated in the current DB. Only summarize a
# stream when it links multiple packets; single packets remain covered by
# conversation and time-window summaries.
MIN_HTTP_STREAM_PACKETS = 2

# Log progress at durable 5% increments. This works better than carriage-return
# progress bars when output is captured by Docker or log collectors.
PROGRESS_STEP_PERCENT = 5


class PercentProgressLogger:
    """Emit compact progress logs at fixed percentage increments."""

    def __init__(self, label: str, total: int, step_percent: int = PROGRESS_STEP_PERCENT):
        self.label = label
        self.total = total
        self.step_percent = max(1, step_percent)
        self._last_bucket = -1

        if total <= 0:
            logger.info("%s progress: no work", self.label)
        else:
            self._log(0, 0)

    def advance(self, current: int) -> None:
        """Log when current work crosses the next percentage bucket."""
        if self.total <= 0:
            return

        percent = min(100, int((current / self.total) * 100))
        bucket = (percent // self.step_percent) * self.step_percent
        if bucket > self._last_bucket:
            self._log(bucket, current)

    def done(self) -> None:
        """Force a final 100% log for non-empty work."""
        if self.total > 0 and self._last_bucket < 100:
            self._log(100, self.total)

    def _log(self, percent: int, current: int) -> None:
        self._last_bucket = percent
        logger.info(
            "%s progress: %d%% (%d/%d)",
            self.label,
            percent,
            current,
            self.total,
        )


def run_analysis(
    mcp_client: MCPClient,
    analyzer: PacketAnalyzer,
    recording_id: int,
    app_details: Optional[str] = None,
    user_actions: Optional[List[UserAction]] = None,
):
    """Group packets into events with summarize, candidate, assignment passes."""

    logger.info("Starting analysis for recording %d", recording_id)

    # The packet ID listing is the stable global iteration order for pass 3.
    raw = mcp_client.list_packet_ids(recording_id)

    packet_ids, packet_timestamps = _parse_packet_id_listing(raw)
    if not packet_ids:
        logger.warning("No packets found for recording %d", recording_id)
        return

    logger.debug(
        "list_packet_ids returned %d packet IDs for recording %d",
        len(packet_ids),
        recording_id,
    )
    logger.info("Found %d packets for recording %d", len(packet_ids), recording_id)

    pcap_start_ms = packet_timestamps[packet_ids[0]] if packet_ids else 0
    facts: Dict[int, PacketFact] = {}
    fetch_errors = 0

    # Cache packet_info once so summary construction and assignment prompts use
    # the same facts and avoid repeated MCP calls for every pass.
    load_progress = PercentProgressLogger("Loading packet facts", len(packet_ids))
    for index, packet_id in enumerate(packet_ids, start=1):
        try:
            packet_info_text = mcp_client.packet_info(packet_id)
        except Exception as e:
            logger.error("Failed to fetch packet_info for %d: %s", packet_id, e)
            fetch_errors += 1
            load_progress.advance(index)
            continue
        facts[packet_id] = _parse_packet_fact(
            packet_id=packet_id,
            timestamp=packet_timestamps.get(packet_id, 0),
            recording_start_ms=pcap_start_ms,
            text=packet_info_text,
        )
        load_progress.advance(index)
    load_progress.done()

    # Empty non-HTTP packets are kept out of LLM grouping; they usually do not
    # carry enough semantic signal for application-level events.
    groupable_ids = [
        packet_id
        for packet_id in packet_ids
        if packet_id in facts and facts[packet_id].is_groupable
    ]
    skipped = len(packet_ids) - len(groupable_ids) - fetch_errors
    logger.info(
        "Using %d groupable packets; skipped %d empty/non-HTTP packets",
        len(groupable_ids),
        skipped,
    )
    if not groupable_ids:
        logger.warning("No groupable packets found for recording %d", recording_id)
        return

    # Tool exposure is read-only; persistence is handled below after validation.
    tools = build_langchain_tools(mcp_client, recording_id, packet_ids)
    recording_context = _format_recording_context(app_details, user_actions)

    logger.info(
        "Pass 1: summarizing conversations, available HTTP streams, and time windows"
    )
    summaries = _build_context_summaries(
        mcp_client=mcp_client,
        analyzer=analyzer,
        recording_id=recording_id,
        facts=facts,
        groupable_ids=groupable_ids,
        app_details=app_details,
        user_actions=user_actions,
        recording_context=recording_context,
    )
    logger.info("Pass 1 complete: %d summaries", len(summaries))

    logger.info("Pass 2: creating event candidates")
    pass2_progress = PercentProgressLogger("Pass 2 candidates", 1)
    candidates = analyzer.propose_event_candidates(
        summaries=summaries,
        user_context=recording_context,
        has_app_details=app_details is not None,
        has_user_actions=bool(user_actions),
    )
    pass2_progress.advance(1)
    pass2_progress.done()
    logger.info("Pass 2 complete: %d event candidates", len(candidates))

    logger.info("Pass 3: assigning packets from structured decisions")
    stats = {
        "total": len(packet_ids),
        "groupable": len(groupable_ids),
        "classified": 0,
        "created": 0,
        "assigned_existing": 0,
        "errors": fetch_errors,
        "skipped": skipped,
    }
    event_state = EventPersistenceState(candidates)
    pass3_progress = PercentProgressLogger("Pass 3 assignments", len(groupable_ids))

    for index, packet_id in enumerate(groupable_ids, start=1):
        fact = facts[packet_id]
        logger.debug(
            "Assigning packet_id %d  (%d / %d)",
            packet_id,
            index,
            len(groupable_ids),
        )

        existing_events_text = mcp_client.events_for_recording(recording_id)
        event_state.remember_existing_events(existing_events_text)

        relevant_summaries = _relevant_summaries(packet_id, summaries)
        relevant_candidates = _relevant_candidates(
            packet_id,
            relevant_summaries,
            candidates,
        )

        decision = analyzer.decide_packet_assignment(
            packet_id=packet_id,
            packet_info_text=fact.text,
            tools=tools,
            summaries=relevant_summaries,
            candidates=relevant_candidates,
            existing_events_text=existing_events_text,
            recording_id=recording_id,
            user_context=format_user_context(
                app_details,
                user_actions,
                fact.offset_ms,
            ),
            has_app_details=app_details is not None,
            has_user_actions=bool(user_actions),
        )
        if decision is None:
            stats["errors"] += 1
            logger.warning("  -> No parseable decision for packet %d", packet_id)
            pass3_progress.advance(index)
            continue

        persisted, created = _validate_and_persist_decision(
            mcp_client=mcp_client,
            packet_id=packet_id,
            decision=decision,
            state=event_state,
        )
        if persisted:
            stats["classified"] += 1
            if created:
                stats["created"] += 1
            else:
                stats["assigned_existing"] += 1
        else:
            stats["errors"] += 1
        pass3_progress.advance(index)
    pass3_progress.done()

    logger.info("=" * 60)
    logger.info("Analysis Complete")
    logger.info("  Total packets:       %d", stats["total"])
    logger.info("  Groupable packets:   %d", stats["groupable"])
    logger.info("  Skipped packets:     %d", stats["skipped"])
    logger.info("  Classified:          %d", stats["classified"])
    logger.info("  New events created:  %d", stats["created"])
    logger.info("  Assigned existing:   %d", stats["assigned_existing"])
    logger.info("  Errors:              %d", stats["errors"])
    logger.info("=" * 60)


class EventPersistenceState:
    """Track event IDs known to the orchestrator during pass-3 assignment."""

    def __init__(self, candidates: Sequence[EventCandidate]):
        # Candidate IDs/descriptions let the LLM refer to pass-2 proposals
        # without creating duplicate events for every packet.
        self.candidate_by_id = {candidate.candidate_id: candidate for candidate in candidates}
        self.candidate_by_description = {
            _normalize_event_text(candidate.description): candidate
            for candidate in candidates
        }
        self.candidate_event_ids: Dict[str, int] = {}
        self.description_event_ids: Dict[str, int] = {}
        self.known_event_ids: set[int] = set()

    def remember_existing_events(self, events_text: str) -> None:
        """Cache persisted event IDs/descriptions parsed from MCP text output."""
        for event_id, description in _parse_events(events_text):
            self.known_event_ids.add(event_id)
            if description:
                self.description_event_ids[_normalize_event_text(description)] = event_id

    def resolve_new_event(self, value: str) -> Tuple[str, Optional[EventCandidate]]:
        """Resolve a model new_event value to a description and candidate."""
        stripped = value.strip()
        candidate = self.candidate_by_id.get(stripped)
        if candidate is not None:
            return candidate.description, candidate

        candidate = self.candidate_by_description.get(_normalize_event_text(stripped))
        if candidate is not None:
            return candidate.description, candidate

        return stripped, None

    def event_id_for_new_event(
        self,
        description: str,
        candidate: Optional[EventCandidate],
    ) -> Optional[int]:
        """Return an already-created event for this candidate/description."""
        if candidate and candidate.candidate_id in self.candidate_event_ids:
            return self.candidate_event_ids[candidate.candidate_id]
        return self.description_event_ids.get(_normalize_event_text(description))

    def remember_created_event(
        self,
        event_id: int,
        description: str,
        candidate: Optional[EventCandidate],
    ) -> None:
        """Record a newly persisted event so later packets can reuse it."""
        self.known_event_ids.add(event_id)
        self.description_event_ids[_normalize_event_text(description)] = event_id
        if candidate is not None:
            self.candidate_event_ids[candidate.candidate_id] = event_id


def _build_context_summaries(
    *,
    mcp_client: MCPClient,
    analyzer: PacketAnalyzer,
    recording_id: int,
    facts: Dict[int, PacketFact],
    groupable_ids: Sequence[int],
    app_details: Optional[str],
    user_actions: Optional[List[UserAction]],
    recording_context: str,
) -> List[ContextSummary]:
    """Build pass-1 summaries from complementary grouping perspectives."""
    summaries: List[ContextSummary] = []
    conversation_groups = _conversation_groups(facts, groupable_ids)
    http_stream_groups = _http_stream_groups(facts, groupable_ids)
    time_windows = _time_windows(facts, groupable_ids, user_actions)
    total_summaries = (
        len(conversation_groups)
        + len(http_stream_groups)
        + len(time_windows)
    )
    progress = PercentProgressLogger("Pass 1 summaries", total_summaries)
    completed = 0

    # Conversation summaries are the primary way to avoid interleaved traffic
    # from unrelated flows.
    for conversation_id, packet_ids in conversation_groups.items():
        label = f"Conversation {conversation_id}"
        try:
            context_text = mcp_client.conversation_packets(
                conversation_id,
                before=0,
                after=MAX_CONTEXT_PACKETS - 1,
            )
        except Exception as e:
            logger.error("Could not fetch %s: %s", label, e)
            context_text = _format_cached_packet_infos(facts, packet_ids)
        summaries.append(
            analyzer.summarize_context(
                summary_id=f"conversation_{conversation_id}",
                kind="conversation",
                label=label,
                packet_ids=packet_ids,
                context_text=context_text,
                user_context=recording_context,
                has_app_details=app_details is not None,
                has_user_actions=bool(user_actions),
            )
        )
        completed += 1
        progress.advance(completed)

    # HTTP stream summaries are optional hints. Missing stream_id metadata is
    # normal, so unstreamed HTTP packets rely on conversation/time-window
    # summaries instead.
    for stream_key, packet_ids in http_stream_groups.items():
        conversation_id, stream_id = stream_key
        label = f"HTTP stream {stream_id}"
        if conversation_id is not None:
            label += f" in conversation {conversation_id}"
        summaries.append(
            analyzer.summarize_context(
                summary_id=f"http_stream_{conversation_id or 'none'}_{stream_id}",
                kind="http_stream",
                label=label,
                packet_ids=packet_ids,
                context_text=_format_cached_packet_infos(facts, packet_ids),
                user_context=recording_context,
                has_app_details=app_details is not None,
                has_user_actions=bool(user_actions),
            )
        )
        completed += 1
        progress.advance(completed)

    # Time windows capture cross-conversation bursts around user actions or
    # short periods of activity.
    for idx, (label, start_ms, end_ms, packet_ids) in enumerate(time_windows, start=1):
        try:
            context_text = mcp_client.packets_in_time_window(
                recording_id,
                start_ms=start_ms,
                end_ms=end_ms,
                max_packets=MAX_CONTEXT_PACKETS,
            )
        except Exception as e:
            logger.error("Could not fetch time window %s: %s", label, e)
            context_text = _format_cached_packet_infos(facts, packet_ids)

        summaries.append(
            analyzer.summarize_context(
                summary_id=f"time_window_{idx}",
                kind="time_window",
                label=label,
                packet_ids=packet_ids,
                context_text=context_text,
                user_context=recording_context,
                has_app_details=app_details is not None,
                has_user_actions=bool(user_actions),
            )
        )
        completed += 1
        progress.advance(completed)

    progress.done()
    return summaries


def _validate_and_persist_decision(
    *,
    mcp_client: MCPClient,
    packet_id: int,
    decision: PacketDecision,
    state: EventPersistenceState,
) -> Tuple[bool, bool]:
    """Validate the model decision and persist only accepted assignments.

    Returns (persisted, created), where created indicates whether this call
    created a new event instead of reusing an existing one.
    """
    if decision.packet_id != packet_id:
        logger.warning(
            "  -> Rejected decision: packet_id mismatch, expected %d got %d",
            packet_id,
            decision.packet_id,
        )
        return False, False

    # Existing-event assignments are accepted only for events observed through
    # events_for_recording or created earlier in this run.
    if decision.event_id is not None:
        if decision.event_id not in state.known_event_ids:
            logger.warning(
                "  -> Rejected decision for packet %d: unknown event_id %d",
                packet_id,
                decision.event_id,
            )
            return False, False
        try:
            result = mcp_client.assign_packet_to_event(packet_id, decision.event_id)
        except Exception as e:
            logger.error(
                "  -> Failed assigning packet %d to event %d: %s",
                packet_id,
                decision.event_id,
                e,
            )
            return False, False
        if result.strip().lower() == "ok":
            logger.info(
                "  -> Assigned to event %d (confidence %.2f)",
                decision.event_id,
                decision.confidence,
            )
            return True, False
        logger.warning("  -> Assignment failed for packet %d: %s", packet_id, result)
        return False, False

    # New-event decisions may point to a pass-2 candidate ID or provide a fresh
    # description. Both are normalized before persistence.
    if not decision.new_event:
        logger.warning("  -> Rejected decision for packet %d: no event target", packet_id)
        return False, False

    description, candidate = state.resolve_new_event(decision.new_event)
    if not description:
        logger.warning("  -> Rejected decision for packet %d: empty new_event", packet_id)
        return False, False

    # Reuse the event already created for this candidate/description.
    existing_event_id = state.event_id_for_new_event(description, candidate)
    if existing_event_id is not None:
        try:
            result = mcp_client.assign_packet_to_event(packet_id, existing_event_id)
        except Exception as e:
            logger.error(
                "  -> Failed assigning packet %d to event %d: %s",
                packet_id,
                existing_event_id,
                e,
            )
            return False, False
        if result.strip().lower() == "ok":
            logger.info(
                "  -> Assigned to candidate event %d (confidence %.2f)",
                existing_event_id,
                decision.confidence,
            )
            return True, False
        logger.warning("  -> Assignment failed for packet %d: %s", packet_id, result)
        return False, False

    # Atomic create+assign prevents orphan events when assignment would fail.
    try:
        result = mcp_client.create_event_and_assign_packet(packet_id, description)
    except Exception as e:
        logger.error("  -> Failed creating event for packet %d: %s", packet_id, e)
        return False, False

    event_id = _parse_created_event_id(result)
    if event_id is None:
        logger.warning("  -> Event creation failed for packet %d: %s", packet_id, result)
        return False, False

    state.remember_created_event(event_id, description, candidate)
    logger.info(
        "  -> Created event %d and assigned packet (confidence %.2f): %s",
        event_id,
        decision.confidence,
        description,
    )
    return True, True


def _parse_packet_id_listing(raw: str) -> Tuple[List[int], Dict[int, int]]:
    """Parse MCP list_packet_ids text into ordered IDs and timestamps."""
    packet_ids: List[int] = []
    packet_timestamps: Dict[int, int] = {}
    for line in raw.splitlines():
        match = re.search(r"packet_id:(\d+)\s+number:\d+\s+timestamp:(\d+)", line)
        if match:
            packet_id = int(match.group(1))
            packet_ids.append(packet_id)
            packet_timestamps[packet_id] = int(match.group(2))
    return packet_ids, packet_timestamps


def _parse_packet_fact(
    *,
    packet_id: int,
    timestamp: int,
    recording_start_ms: int,
    text: str,
) -> PacketFact:
    """Extract the fields the orchestrator needs from packet_info text."""
    offset_match = re.search(
        r"^timestamp offset:\s*(-?\d+)\s+ms",
        text,
        flags=re.MULTILINE,
    )
    offset_ms = (
        int(offset_match.group(1))
        if offset_match is not None
        else timestamp - recording_start_ms
    )

    conversation_match = re.search(
        r"^conversation_id:\s*(\d+)\s*$",
        text,
        flags=re.MULTILINE,
    )
    protocol_match = re.search(
        r"^app protocol:\s*(.+)$",
        text,
        flags=re.MULTILINE,
    )
    payload_match = re.search(
        r"^payload length:\s*(\d+)\s+bytes",
        text,
        flags=re.MULTILINE,
    )

    return PacketFact(
        packet_id=packet_id,
        timestamp=timestamp,
        offset_ms=offset_ms,
        conversation_id=(
            int(conversation_match.group(1)) if conversation_match else None
        ),
        app_protocol=(protocol_match.group(1).strip() if protocol_match else "unknown"),
        payload_length=int(payload_match.group(1)) if payload_match else 0,
        has_http="http header:" in text,
        text=text,
    )


def _conversation_groups(
    facts: Dict[int, PacketFact],
    packet_ids: Sequence[int],
) -> Dict[int, List[int]]:
    """Collect groupable packets by database conversation ID."""
    groups: Dict[int, List[int]] = defaultdict(list)
    for packet_id in packet_ids:
        conversation_id = facts[packet_id].conversation_id
        if conversation_id is not None:
            groups[conversation_id].append(packet_id)
    return dict(groups)


def _http_stream_groups(
    facts: Dict[int, PacketFact],
    packet_ids: Sequence[int],
) -> Dict[Tuple[Optional[int], int], List[int]]:
    """Group packets only when explicit HTTP stream metadata exists.

    Most HTTP packets currently have no stream_id in the database. That is not
    treated as evidence for a separate stream; those packets remain covered by
    conversation and time-window summaries.
    """
    groups: Dict[Tuple[Optional[int], int], List[int]] = defaultdict(list)
    for packet_id in packet_ids:
        fact = facts[packet_id]
        for stream_id in _parse_http_stream_ids(fact.text):
            groups[(fact.conversation_id, stream_id)].append(packet_id)
    return {
        stream_key: grouped_packet_ids
        for stream_key, grouped_packet_ids in groups.items()
        if len(grouped_packet_ids) >= MIN_HTTP_STREAM_PACKETS
    }


def _parse_http_stream_ids(text: str) -> List[int]:
    """Extract any explicit HTTP stream IDs present in packet_info text."""
    return [
        int(match.group(1))
        for match in re.finditer(r"^http stream_id:\s*(\d+)\s*$", text, re.MULTILINE)
    ]


def _time_windows(
    facts: Dict[int, PacketFact],
    packet_ids: Sequence[int],
    user_actions: Optional[List[UserAction]],
) -> List[Tuple[str, int, int, List[int]]]:
    """Create pass-1 time windows from user actions or automatic chunks."""
    if user_actions:
        windows: List[Tuple[str, int, int, List[int]]] = []
        for action in user_actions[:MAX_TIME_WINDOW_SUMMARIES]:
            start_ms = max(0, action.offset_ms - 2_000)
            end_ms = action.offset_ms + 5_000
            ids = [
                packet_id
                for packet_id in packet_ids
                if start_ms <= facts[packet_id].offset_ms <= end_ms
            ]
            if ids:
                windows.append(
                    (
                        f"User action at {action.offset_ms} ms: {action.description}",
                        start_ms,
                        end_ms,
                        ids,
                    )
                )
        return windows

    # Without user actions, split the recording into bounded temporal chunks.
    sorted_ids = sorted(packet_ids, key=lambda packet_id: facts[packet_id].offset_ms)
    windows = []
    current_ids: List[int] = []
    current_start: Optional[int] = None

    for packet_id in sorted_ids:
        offset_ms = facts[packet_id].offset_ms
        if current_start is None:
            current_start = offset_ms
        if (
            current_ids
            and (
                offset_ms - current_start > TIME_WINDOW_MS
                or len(current_ids) >= TIME_WINDOW_PACKET_LIMIT
            )
        ):
            current_end = facts[current_ids[-1]].offset_ms
            windows.append(
                (
                    f"Traffic window {current_start}..{current_end} ms",
                    current_start,
                    current_end,
                    current_ids,
                )
            )
            current_ids = []
            current_start = offset_ms
        current_ids.append(packet_id)

    if current_ids and current_start is not None:
        current_end = facts[current_ids[-1]].offset_ms
        windows.append(
            (
                f"Traffic window {current_start}..{current_end} ms",
                current_start,
                current_end,
                current_ids,
            )
        )

    return windows[:MAX_TIME_WINDOW_SUMMARIES]


def _format_cached_packet_infos(
    facts: Dict[int, PacketFact],
    packet_ids: Iterable[int],
) -> str:
    """Render cached packet_info blocks while respecting prompt-size caps."""
    parts: List[str] = []
    for packet_id in list(packet_ids)[:MAX_CONTEXT_PACKETS]:
        parts.append(f"=== packet_id:{packet_id} ===\n{facts[packet_id].text}")
    return "\n\n".join(parts) if parts else "(no packets)"


def _relevant_summaries(
    packet_id: int,
    summaries: Sequence[ContextSummary],
    limit: int = 12,
) -> List[ContextSummary]:
    """Prefer summaries that directly contain the packet under assignment."""
    direct = [summary for summary in summaries if packet_id in summary.packet_ids]
    if len(direct) >= limit:
        return direct[:limit]

    remaining = [summary for summary in summaries if summary not in direct]
    return (direct + remaining[: limit - len(direct)])[:limit]


def _relevant_candidates(
    packet_id: int,
    summaries: Sequence[ContextSummary],
    candidates: Sequence[EventCandidate],
    limit: int = 12,
) -> List[EventCandidate]:
    """Prefer candidates connected to the packet or its relevant summaries."""
    summary_ids = {summary.summary_id for summary in summaries}
    direct = [
        candidate
        for candidate in candidates
        if packet_id in candidate.packet_ids
        or any(summary_id in summary_ids for summary_id in candidate.source_summary_ids)
    ]
    if len(direct) >= limit:
        return direct[:limit]

    remaining = [candidate for candidate in candidates if candidate not in direct]
    return (direct + remaining[: limit - len(direct)])[:limit]


def _format_recording_context(
    app_details: Optional[str],
    user_actions: Optional[List[UserAction]],
) -> str:
    """Render recording-level user/app context for pass-1 and pass-2 prompts."""
    parts: List[str] = []
    if app_details:
        parts.append(
            "=== Application Details ===\n"
            f"{app_details}\n"
            "=== End Application Details ==="
        )
    if user_actions:
        lines = ["=== User Actions ==="]
        for action in user_actions:
            lines.append(f"  [{action.offset_ms} ms] {action.description}")
        lines.append("=== End User Actions ===")
        parts.append("\n".join(lines))
    return "\n\n".join(parts)


def _parse_events(events_text: str) -> List[Tuple[int, str]]:
    """Parse MCP event listing text into event IDs and descriptions."""
    events: List[Tuple[int, str]] = []
    for line in events_text.splitlines():
        match = re.search(r"\bevent_id:(\d+)\s+description:(.*?)\s+start:", line)
        if match:
            events.append((int(match.group(1)), match.group(2).strip()))
            continue
        id_match = re.search(r"\bevent_id:(\d+)\b", line)
        if id_match:
            events.append((int(id_match.group(1)), ""))
    return events


def _parse_created_event_id(result: str) -> Optional[int]:
    """Extract event_id from create_event_and_assign_packet output."""
    match = re.search(r"\bevent_id:(\d+)\b", result)
    return int(match.group(1)) if match else None


def _normalize_event_text(value: str) -> str:
    """Normalize event descriptions for duplicate detection."""
    return re.sub(r"\s+", " ", value.strip()).casefold()
