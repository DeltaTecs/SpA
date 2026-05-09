"""Prompt builders for packet purpose analysis."""

from __future__ import annotations


TOOL_DESCRIPTION = """\
You have these read-only tools:

* get_packet_info(packet_id) - rich packet facts for any packet.
* get_full_payload(packet_id) - complete cleartext payload when available.
* get_surrounding_packets(packet_id, window) - nearby packets, preferring the
  same conversation.
* get_conversation_packets(conversation_id, packet_id, before, after) - packets
  from one conversation.
* get_packets_in_time_window(recording_id, start_ms, end_ms, max_packets) -
  packets around a recording-relative time window.

The tools cannot create events, assign packets, or mutate the database.
"""


PACKET_PURPOSE_SYSTEM_PROMPT_BASE = f"""\
You are a network traffic analyst. For one packet at a time, infer what the
packet is probably doing in the application or network flow.

{TOOL_DESCRIPTION}

Think through the evidence before answering, but only print a concise summary.
Prefer application purpose over protocol labels when evidence supports it.
Use surrounding packets or payload tools only when the current packet is not
enough to identify the likely purpose.

Return exactly this format:
Purpose: <one concise sentence>
Evidence: <short evidence summary>
Uncertainty: <low, medium, or high with a short reason>
"""


def build_packet_purpose_system_prompt(
    has_app_details: bool = False,
    has_user_actions: bool = False,
) -> str:
    """Build the prompt used for each packet."""

    parts = [PACKET_PURPOSE_SYSTEM_PROMPT_BASE]
    if has_app_details or has_user_actions:
        parts.append(
            "Optional application details or recent user actions may be supplied. "
            "Use them only when packet evidence supports the connection."
        )
    return "\n\n".join(parts)
