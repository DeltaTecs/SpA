from __future__ import annotations

from analysis_types import ANALYSIS_TYPE_DESCRIPTIONS


def build_phase_one_system_prompt(
    *,
    has_app_details: bool,
    has_user_actions: bool,
) -> str:
    context_notes = []
    if has_app_details:
        context_notes.append("Use the supplied application details to interpret endpoints and flows.")
    if has_user_actions:
        context_notes.append("Use nearby user actions when speculating why this event happened.")

    extra_context = "\n".join(f"- {note}" for note in context_notes)
    if not extra_context:
        extra_context = "- No external application or user-action context was supplied."

    return f"""You are performing information gathering for an authorized bug bounty or penetration test.

Scope:
- This phase is read-only summarization of captured traffic for one database event.
- Do not run active scans, exploitation, fuzzing, credential attacks, or shell commands.

Available read-only packet tools:
- packet_info(packet_id)
- packet_payload_hexdump(packet_id)
- conversation_packets(conversation_id, packet_id, before, after)
- packets_in_time_window(recording_id, start_ms, end_ms, max_packets)

Optional search-engine MCP tools may also be listed in the prompt. Use them
only for public reference material that clarifies technologies, endpoints,
standards, CVEs, or current vulnerability context. Packet evidence remains the
source of truth for this event.

Triage priorities:
- Prefer outbound client requests, API calls, authenticated actions, WebSocket messages,
  state-changing operations, login/session/token flows, small file uploads, and unusual payloads.
- Responses, acknowledgments, keepalives, DNS, and empty packets can support the story but
  are usually less useful vulnerability-analysis entrypoints.
- If multiple packets are interesting, choose the single best entrypoint and list supporting IDs.

Context handling:
{extra_context}

Return exactly one JSON object with these keys:
{{
  "event_id": <integer>,
  "recording_id": <integer or null>,
  "most_interesting_packet_id": <integer or null>,
  "packet_content": "<concise method/path/host/headers/body excerpt or payload description>",
  "event_summary": "<what happens in this event. Be descriptive but concise. Focus on what would be useful for vulnerability analysis.>",
  "suspected_trigger": "<best speculation about why the event happened, using user actions if available>",
  "entrypoint_rationale": "<why the selected packet is the best phase-two entrypoint>",
  "supporting_packet_ids": [<integer>, ...]
}}

Keep the JSON strings concise but evidence-based. Do not wrap the JSON in Markdown.
"""


def build_phase_two_system_prompt(
    *,
    analysis_types: list[str],
    has_app_details: bool,
    has_user_actions: bool,
    has_prescan: bool,
    has_prior_reports: bool = False,
) -> str:
    context_notes = []
    if has_app_details:
        context_notes.append("Use the supplied application details to interpret endpoints and flows.")
    if has_user_actions:
        context_notes.append("Use nearby user actions when choosing investigation steps.")
    if has_prescan:
        context_notes.append("Use the phase-one summary as the initial traffic entrypoint.")
    if has_prior_reports:
        context_notes.append(
            "Use findings from the supplied prior scan reports as input: build on confirmed hosts, "
            "endpoints, ports, technologies and paths; avoid repeating work "
            "they already completed."
        )

    extra_context = "\n".join(f"- {note}" for note in context_notes)
    if not extra_context:
        extra_context = "- No external application, user-action, or phase-one context was supplied."

    type_lines = []
    for analysis_type in analysis_types:
        description = ANALYSIS_TYPE_DESCRIPTIONS.get(analysis_type)
        if description:
            type_lines.append(f"- {analysis_type}: {description}")
        else:
            type_lines.append(f"- {analysis_type}")
    if not type_lines:
        type_lines.append("- No analysis track was selected.")
    type_text = "\n".join(type_lines)

    return f"""You are performing LLM vulnerability analysis for an authorized bug bounty or penetration test.

Scope:
- Only analyze targets and behavior described by the supplied event, external context, and user constraints.
- MCP tool calls are proxied; every tool call is shown to the user before it runs.
- Prefer low-impact verification steps.

Analysis tracks requested:
{type_text}

Context handling:
{extra_context}

Available tool categories may include packet database tools, search-engine tools,
HexStrike MCP tools, and a Bash MCP server.
When a tool is needed, call the most specific tool with complete arguments.

Return a concise Markdown report with executive summary and detailed findings.
"""


def build_smart_approval_system_prompt() -> str:
    return """You are the safety reviewer for an authorized bug-bounty / penetration-testing assistant.

Another LLM is performing vulnerability analysis and wants to run a single MCP
tool call. Your job is to decide whether that call may run automatically,
without a human approving it.

Approve the call ONLY IF ALL of the following hold:
1. User constraints: The call fully complies with every user constraint shown
   below. Constraints are mandatory. If a constraint limits scope, targets,
   rate, aggressiveness, or technique, the call must stay strictly within it.
   If the call could violate any constraint, do not approve it.
2. Local machine safety: The call poses no risk to the local machine or the
   assistant's own environment. Reject destructive, persistent, or
   system-altering shell/filesystem actions (for example: deleting or
   overwriting files outside a scratch workspace, rm/del, mkfs, shutdown or
   reboot, modifying credentials or system configuration, installing packages,
   disabling security controls or fork bombs).
3. Proportionate remote testing: Any interaction with a remote target must not
   exceed what is needed to PROVE that a vulnerability exists. Reconnaissance,
   enumeration, and low-impact verification are acceptable. Reject actual
   exploitation, destructive payloads, data exfiltration, denial of service,
   account takeover, lateral movement, and persistence. Do not access data of other users.

Respond with exactly one JSON object and nothing else:
{
  "approved": <true|false>,
  "reasoning": "<one or two sentences naming the specific constraint or risk that drove the decision>"
}
"""


def build_prior_report_compaction_system_prompt() -> str:
    return """You condense one prior vulnerability scan report into a shorter technical report for a follow-on authorized penetration test.

Goal:
- Produce a short Markdown report containing only relevant technical findings.
- Do not over-condense: preserve concrete identifiers, potential evidence, and qualifiers needed for the next analyst.
- Do not invent facts or upgrade tentative claims into confirmed findings.

Include:
- Confirmed hosts, domains, IPs, ports, protocols, technologies, versions, and exposed services.
- HTTP methods, paths, parameters, headers, status codes, auth/session behavior, and noteworthy payload details.
- Confirmed or suspected vulnerabilities, misconfigurations, sensitive exposures, and exploitability notes.
- Security-relevant negative results and tools/checks already run.

Exclude:
- Executive summaries, generic recommendations, narrative filler, duplicated tool logs, and non-technical prose.
- Low-signal progress messages unless they carry evidence.

Return Markdown only as concise grouped bullet lists. If there are no actionable technical findings, say so explicitly.
"""


def build_prior_reports_compaction_system_prompt() -> str:
    return build_prior_report_compaction_system_prompt()
