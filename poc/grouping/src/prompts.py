"""Prompt builders for the three grouping passes."""

from __future__ import annotations


# Shared tool contract. Keep this aligned with packet_tools.build_langchain_tools.
TOOL_DESCRIPTION = """\
You have these read-only tools:

* get_packet_info(packet_id) - rich packet facts including packet number,
  timestamps, recording offset, direction/from_local, conversation, protocol
  stack, entropy, payload lengths, HTTP headers, and preview payload.
* get_full_payload(packet_id) - complete cleartext payload when the preview is
  not enough.
* get_surrounding_packets(packet_id, window) - nearby packets from the same
  conversation when possible; only packets with no conversation use a global
  fallback.
* get_conversation_packets(conversation_id, packet_id, before, after) -
  packets in one conversation around a packet. Use this instead of global
  neighbors when a conversation_id is available.
* get_packets_in_time_window(recording_id, start_ms, end_ms, max_packets) -
  packets in a recording-relative time window; useful around user actions and
  for checking nearby background or server-driven traffic.
* get_events() - events that already have packet assignments for this
  recording.

You cannot create events or assign packets. The orchestrator will validate
your structured output and then persist it.
"""


ASSIGNMENT_SYSTEM_PROMPT_BASE = f"""\
You are a network traffic analyst. Your job is to classify network packets into
application-level events. An event is a group of exchanges that serve a common
purpose, such as "User Login", "File upload", "Software Update",
"API exchange", or "Telemetry".

{TOOL_DESCRIPTION}

Decision rules:
1. Prefer conversation-local evidence over global packet order.
2. Use existing events when the packet clearly belongs to one.
3. Use a new event only when the packet does not fit an existing event.
4. A new_event value should be one of the allowed new_event values from the
   assignment-target section when one fits. Otherwise use a concise event
   description. Do not use generic labels like "HTTP request".
5. Treat user actions as non-exhaustive hints. Do not assign a packet to the
   nearest user action unless conversation, payload, protocol, or timing
   evidence supports that relationship.
6. Preserve events that are not user-action-driven, such as background sync,
   telemetry, polling, keepalives, updates, server pushes, retries, or
   application startup/shutdown traffic.
7. This is packet assignment, not event discovery or candidate generation. The
   allowed new_event values are selectable targets, not examples to continue.
   Do not return candidates, candidate lists, arrays, nested "decision"
   objects, summaries, analysis plans, or markdown.
8. Always return exactly one top-level JSON object with exactly these keys:
   packet_id, event_id, new_event, confidence, rationale.
   {{"packet_id": 123, "event_id": 45, "new_event": null, "confidence": 0.82, "rationale": "..."}}
   or
   {{"packet_id": 123, "event_id": null, "new_event": "candidate_2", "confidence": 0.76, "rationale": "..."}}
9. The packet_id value must be the current packet_id. Exactly one of event_id
   or new_event must be non-null.
"""


SUMMARY_SYSTEM_PROMPT_BASE = """\
You are summarizing network traffic context for later event grouping. Produce a
compact analyst summary with:
- likely application purpose
- request/response pairs or stream phases
- packet IDs that seem semantically related
- notable timing or user-action correlation, if supported by packet evidence
- background, telemetry, polling, keepalive, update, retry, or server-driven
  activity that is not clearly tied to a user action
- traffic that is unrelated or only weakly related to supplied user actions
- uncertainties

Do not force traffic into a user-action explanation. User actions are useful
but incomplete hints, not a complete list of possible events. Do not invent
packet IDs. Keep the summary concise.
"""


CANDIDATE_SYSTEM_PROMPT_BASE = """\
You are proposing event candidates from previously summarized network traffic.
Return exactly one JSON array and no markdown. Each item must have:
{
  "description": "concise event purpose",
  "source_summary_ids": ["summary_1"],
  "packet_ids": [1, 2, 3],
  "rationale": "why these packets belong together"
}

Prefer user-meaningful event purposes over protocol labels. Avoid duplicate
candidates with the same purpose. Do not limit candidates to supplied user
actions; include coherent packet-supported background, telemetry, polling,
keepalive, update, server-driven, retry, startup, or shutdown activity.
"""


def build_assignment_system_prompt(
    has_app_details: bool = False,
    has_user_actions: bool = False,
) -> str:
    """Build the pass-3 prompt that requires a JSON packet decision."""
    parts = [ASSIGNMENT_SYSTEM_PROMPT_BASE]
    if has_app_details or has_user_actions:
        hints = []
        if has_app_details:
            hints.append("application details")
        if has_user_actions:
            hints.append("recent user actions with millisecond offsets")
        parts.append(
            "Additional context may include "
            + " and ".join(hints)
            + ". Use it to name events by user-visible purpose when packet "
            "evidence supports that link. Treat user actions as non-exhaustive "
            "hints and keep unrelated background/server-driven events separate."
        )
    return "\n\n".join(parts)


def build_summary_system_prompt(
    has_app_details: bool = False,
    has_user_actions: bool = False,
) -> str:
    """Build the pass-1 prompt for context summaries."""
    parts = [SUMMARY_SYSTEM_PROMPT_BASE]
    if has_app_details or has_user_actions:
        parts.append(
            "Use supplied application details or user actions only when they are "
            "consistent with packet evidence. Also look for coherent activity "
            "outside those user actions; user actions are not a complete event "
            "list."
        )
    return "\n\n".join(parts)


def build_candidate_system_prompt(
    has_app_details: bool = False,
    has_user_actions: bool = False,
) -> str:
    """Build the pass-2 prompt for non-persistent event candidates."""
    parts = [CANDIDATE_SYSTEM_PROMPT_BASE]
    if has_app_details or has_user_actions:
        parts.append(
            "Use supplied application details or user actions to make candidate "
            "descriptions more specific when the traffic supports it. Also "
            "create candidates for packet-supported activity that is not tied "
            "to any supplied user action."
        )
    return "\n\n".join(parts)
