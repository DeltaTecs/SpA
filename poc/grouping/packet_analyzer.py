#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
packet_analyzer.py

Analyze network packets using LangChain (Ollama) with tool-calling.
The LLM accesses packet data exclusively through MCP server tools exposed
via an HTTP/SSE bridge -- no direct database access from this module.

Usage:
    python packet_analyzer.py --recording-id 1 \
        --mcp-url http://mcp-packet-db:8765 \
        [--model qwen3:8b] \
        [--ollama-host http://localhost:11434]
"""
from __future__ import annotations

import argparse
import logging
import re
import sys
from dataclasses import dataclass
from typing import List, Optional, Tuple

try:
    from langchain_ollama import ChatOllama
    from langchain_core.messages import HumanMessage, SystemMessage, AIMessage, ToolMessage
    from langchain_core.tools import tool as langchain_tool
except ImportError:
    raise ImportError(
        "langchain packages are required. "
        "Install with: pip install langchain langchain-ollama langchain-community"
    )

from mcp_client import MCPClient

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Suppress noisy HTTP client logs from httpx/httpcore
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)


# ============================================================================
# User-intend / app-details helpers
# ============================================================================

@dataclass
class UserAction:
    """A single user action parsed from the intend file."""
    offset_ms: int          # milliseconds since pcap start
    description: str        # human-readable action text


def parse_intend_file(path: str) -> List[UserAction]:
    """
    Parse a user-intend file.

    Expected format (one action per line)::

        MM:SS description text

    Returns a list of UserAction sorted by offset_ms.
    """
    actions: List[UserAction] = []
    with open(path, encoding="utf-8") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line:
                continue
            m = re.match(r"^(\d+):(\d{2})\s+(.+)$", line)
            if not m:
                logger.debug("Skipping unparseable intend line: %s", line)
                continue
            minutes, seconds = int(m.group(1)), int(m.group(2))
            offset_ms = (minutes * 60 + seconds) * 1000
            actions.append(UserAction(offset_ms=offset_ms, description=m.group(3)))
    actions.sort(key=lambda a: a.offset_ms)
    logger.info("Parsed %d user actions from %s", len(actions), path)
    return actions


def load_app_details(path: str) -> str:
    """Read app_details.txt and return its content as a string."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read().strip()
    logger.info("Loaded app details from %s (%d chars)", path, len(text))
    return text


def recent_user_actions(
    actions: List[UserAction],
    packet_offset_ms: int,
    n: int = 5,
) -> List[Tuple[UserAction, int]]:
    """
    Return up to *n* user actions whose offset is <= packet_offset_ms,
    most-recent first.  Each entry is (action, delta_ms) where delta_ms
    is ``packet_offset_ms - action.offset_ms`` (always >= 0).
    """
    preceding = [
        (a, packet_offset_ms - a.offset_ms)
        for a in actions
        if a.offset_ms <= packet_offset_ms
    ]
    # most-recent first (smallest delta first)
    preceding.sort(key=lambda t: t[1])
    return preceding[:n]


def format_user_context(
    app_details: Optional[str],
    actions: Optional[List[UserAction]],
    packet_offset_ms: Optional[int],
) -> str:
    """
    Build a text block with app details and recent user actions that can
    be prepended to the per-packet prompt.
    """
    parts: List[str] = []

    if app_details:
        parts.append(
            "=== Application Details ===\n"
            f"{app_details}\n"
            "=== End Application Details ==="
        )

    if actions and packet_offset_ms is not None:
        recent = recent_user_actions(actions, packet_offset_ms)
        if recent:
            lines = ["=== Recent User Actions (most recent first) ==="]
            for action, delta_ms in recent:
                lines.append(f"  [{delta_ms:+d} ms]  {action.description}")
            lines.append("=== End User Actions ===")
            parts.append("\n".join(lines))

    return "\n\n".join(parts)


# ============================================================================
# LangChain Tools -- wrappers that the LLM can call
# ============================================================================

def build_langchain_tools(mcp: MCPClient, recording_id: int, packet_ids: List[int]):
    """
    Build LangChain tool definitions that delegate to the MCP server.

    The LLM receives these tools so it can autonomously:
      - inspect the current packet and nearby packets
      - request the full (non-truncated) payload when necessary
      - query and manage events

    Returns (tools_list, tracker) where tracker.assigned is set to True
    once assign_to_event completes successfully, and tracker.event_id /
    tracker.description capture what happened.
    """

    class ToolTracker:
        """Tracks whether the LLM successfully assigned the packet."""
        def __init__(self):
            self.assigned = False
            self.event_id: Optional[int] = None
            self.created_description: Optional[str] = None

        def reset(self):
            self.assigned = False
            self.event_id = None
            self.created_description = None

    tracker = ToolTracker()

    @langchain_tool
    def get_packet_info(packet_id: int) -> str:
        """Retrieve flow, protocol layers, HTTP headers, and a 256-byte
        payload preview for a packet.  Use this to inspect ANY packet --
        not just the current one.  You may inspect surrounding packets
        (nearby packet IDs) for additional context when classifying."""
        return mcp.packet_info(packet_id)

    @langchain_tool
    def get_full_payload(packet_id: int) -> str:
        """Retrieve the FULL cleartext application payload as a hex+ASCII
        hexdump.  Use this when the 256-byte preview from get_packet_info
        is truncated and you need to see the complete payload to make a
        classification decision."""
        return mcp.call_tool("packet_payload_hexdump", {"packet_id": packet_id})

    @langchain_tool
    def get_surrounding_packets(packet_id: int, window: int = 2) -> str:
        """Return flow, protocol, header, and payload-preview info for
        packets surrounding the given packet_id (up to *window* packets
        before and after).  This lets you examine neighbouring traffic
        in the same recording to better understand the context of the
        current packet (e.g. a request followed by its response)."""
        try:
            idx = packet_ids.index(packet_id)
        except ValueError:
            return f"packet_id {packet_id} not in current recording"

        start = max(0, idx - window)
        end = min(len(packet_ids), idx + window + 1)
        neighbours = packet_ids[start:end]
        parts: list[str] = []
        for pid in neighbours:
            marker = "  <-- current" if pid == packet_id else ""
            header = f"=== packet_id:{pid}{marker} ==="
            info = mcp.packet_info(pid)
            parts.append(f"{header}\n{info}")
        return "\n\n".join(parts)

    @langchain_tool
    def get_events(recording_id_unused: int = 0) -> str:
        """Return all events that currently exist for this recording.
        Each event has an event_id and a short description.
        Use this before deciding whether to create a new event or assign
        the packet to an existing one."""
        return mcp.events_for_recording(recording_id)

    @langchain_tool
    def create_new_event(description: str) -> str:
        """Create a brand-new event.
        Provide a short, descriptive label (e.g. 'TLS handshake',
        'User login request/response').
        Returns the new event_id."""
        result = mcp.create_event(description)
        tracker.created_description = description
        return result

    @langchain_tool
    def assign_to_event(packet_id: int, event_id: int) -> str:
        """Assign a packet to an existing event.  This also widens the
        event time range to include the packet timestamp.
        Returns 'ok' on success."""
        result = mcp.assign_packet_to_event(packet_id, event_id)
        if "ok" in result.lower():
            tracker.assigned = True
            tracker.event_id = event_id
        return result

    tools = [
        get_packet_info,
        get_full_payload,
        get_surrounding_packets,
        get_events,
        create_new_event,
        assign_to_event,
    ]
    return tools, tracker


# ============================================================================
# Packet Analyzer -- orchestrates the LLM tool-calling loop
# ============================================================================

SYSTEM_PROMPT_BASE = """\
You are a network traffic analyst.  Your job is to classify network packets
into application-level events. An event is a group of data exchanges that serve a common purpose, such as "User Login", "File upload", "Software Update", "API exchange", or "Telemetry".

You have the following tools at your disposal:

* **get_packet_info(packet_id)** -- get flow info, protocol layers,
  HTTP headers, and a 256-byte payload preview for ANY packet.
* **get_full_payload(packet_id)** -- get the COMPLETE cleartext payload
  when the 256-byte preview is not enough.
* **get_surrounding_packets(packet_id, window)** -- retrieve info for
  nearby packets so you can inspect preceding/following traffic for
  context (e.g. request <-> response pairs).
* **get_events()** -- list all events that exist so far for this recording.
* **create_new_event(description)** -- create a new event.
  Returns the event_id.
* **assign_to_event(packet_id, event_id)** -- assign the current packet
  to an event and adjust the event time range.

**Workflow for each packet you are given:**
1. You will receive the packet_id and basic info. Study it.
2. If you need more context, call get_surrounding_packets and/or
   get_packet_info on specific neighbours, or get_full_payload.
3. Call get_events() to see existing events.
4. Decide: does this packet belong to an existing event, or should a new
   one be created?
5. Either call assign_to_event OR call create_new_event followed by
   assign_to_event. When creating an event, be as specific as possible but concise. Do not label events 'HTTP request', instead describe what purpose the request serves if possible.

Important:
- Always end with an assign_to_event call so the packet is persisted.
- You may call multiple tools before deciding.
- Investigate atleast 2 packets around the current packet for better context.
- Group related packets (e.g. HTTP request + response) into the same event. Prefer assigning the packet to an existing event if it fits, rather than creating a new one.
"""


class PacketAnalyzer:
    """Drive LLM-based packet classification via tool calling."""

    def __init__(
        self,
        model: str = "qwen3:8b",
        ollama_host: str = "http://localhost:11434",
    ):
        self.model_name = model
        self.ollama_host = ollama_host
        self.llm = None

    def initialize(self):
        logger.info("Initializing ChatOllama with model: %s", self.model_name)
        self.llm = ChatOllama(
            model=self.model_name,
            base_url=self.ollama_host,
            temperature=0.1,
        )
        logger.info("LLM initialized successfully")

    # ------------------------------------------------------------------

    @staticmethod
    def _build_system_prompt(
        has_app_details: bool = False,
        has_user_actions: bool = False,
    ) -> str:
        """Assemble the system prompt, adding context-awareness paragraphs
        only when the corresponding data is actually provided."""
        parts = [SYSTEM_PROMPT_BASE]
        if has_app_details or has_user_actions:
            hints: List[str] = []
            if has_app_details:
                hints.append(
                    "a description of the application that generated the traffic"
                )
            if has_user_actions:
                hints.append(
                    "recent user actions with millisecond offsets relative to "
                    "the packet under analysis"
                )
            parts.insert(
                1,
                "You will receive additional context: "
                + " and ".join(hints)
                + ".  Use this information to better understand the purpose of "
                "each packet and to create more meaningful event descriptions.",
            )
        return "\n\n".join(parts)

    def analyze_packet(
        self,
        packet_id: int,
        packet_info_text: str,
        tools: list,
        *,
        max_rounds: int = 10,
        user_context: str = "",
        has_app_details: bool = False,
        has_user_actions: bool = False,
    ) -> Optional[str]:
        """
        Run one tool-calling conversation for a single packet.

        Returns a short summary string or None on error.
        """
        llm_with_tools = self.llm.bind_tools(tools)

        logger.info(
            ">>> Inspecting packet_id=%d – sending to LLM for classification",
            packet_id,
        )

        system_prompt = self._build_system_prompt(
            has_app_details=has_app_details,
            has_user_actions=has_user_actions,
        )

        user_prompt_parts = []
        if user_context:
            user_prompt_parts.append(user_context)
        user_prompt_parts.append(
            f"Classify the following packet (packet_id={packet_id}).\n\n"
            f"{packet_info_text}\n\n"
            "Use the tools to inspect surrounding packets or retrieve "
            "full payloads if you need more context. Then assign the "
            "packet to an existing or new event."
        )

        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content="\n\n".join(user_prompt_parts)),
        ]

        for round_num in range(max_rounds):
            try:
                response = llm_with_tools.invoke(messages)
            except Exception as e:
                logger.error("LLM invocation failed (round %d): %s", round_num, e)
                return None

            messages.append(response)

            # If no tool calls, the LLM is done
            if not getattr(response, "tool_calls", None):
                return response.content

            # Execute each tool call
            for tc in response.tool_calls:
                tool_name = tc["name"]
                tool_args = tc["args"]
                logger.debug("  Tool call: %s(%s)", tool_name, tool_args)

                # Find matching tool and invoke
                result = "(tool not found)"
                for t in tools:
                    if t.name == tool_name:
                        try:
                            result = t.invoke(tool_args)
                        except Exception as e:
                            result = f"Error: {e}"
                        break

                messages.append(
                    ToolMessage(content=str(result), tool_call_id=tc["id"])
                )

        logger.warning("Max tool-call rounds reached for packet %d", packet_id)
        return messages[-1].content if messages else None


# ============================================================================
# Main Analysis Loop
# ============================================================================

def run_analysis(
    mcp_client: MCPClient,
    analyzer: PacketAnalyzer,
    recording_id: int,
    app_details: Optional[str] = None,
    user_actions: Optional[List[UserAction]] = None,
):
    """Iterate over all packets in a recording, asking the LLM to classify each."""
    logger.info("Starting analysis for recording %d", recording_id)

    # Fetch ordered packet IDs (with timestamps) from MCP
    raw = mcp_client.list_packet_ids(recording_id)
    logger.debug("list_packet_ids response:\n%s", raw)

    packet_ids: List[int] = []
    packet_timestamps: dict[int, int] = {}   # packet_id -> epoch ms
    for line in raw.splitlines():
        m = re.search(r"packet_id:(\d+)\s+number:\d+\s+timestamp:(\d+)", line)
        if m:
            pid_val = int(m.group(1))
            ts_val = int(m.group(2))
            packet_ids.append(pid_val)
            packet_timestamps[pid_val] = ts_val

    if not packet_ids:
        logger.warning("No packets found for recording %d", recording_id)
        return

    logger.info("Found %d packets for recording %d", len(packet_ids), recording_id)

    # Determine the recording start time (epoch ms of the first packet)
    # so we can convert user-action offsets to absolute timestamps.
    pcap_start_ms = packet_timestamps[packet_ids[0]] if packet_ids else 0

    # Build LangChain tools once
    tools, tracker = build_langchain_tools(mcp_client, recording_id, packet_ids)

    stats = {"total": len(packet_ids), "classified": 0, "errors": 0}

    for i, pid in enumerate(packet_ids):
        logger.info("Analyzing packet_id %d  (%d / %d)", pid, i + 1, len(packet_ids))

        # Pre-fetch basic info so the LLM starts with context
        try:
            pkt_info = mcp_client.packet_info(pid)
        except Exception as e:
            logger.error("  Failed to fetch packet_info for %d: %s", pid, e)
            stats["errors"] += 1
            continue

        # Skip packets with empty payload and no HTTP info
        if "app payload (first 256 bytes): (empty)" in pkt_info and "http header:" not in pkt_info:
            logger.debug("  Skipping packet_id %d (no payload, not HTTP)", pid)
            continue

        # Build user context (app details + recent user actions)
        pkt_offset_ms: Optional[int] = None
        if pid in packet_timestamps:
            pkt_offset_ms = packet_timestamps[pid] - pcap_start_ms

        user_context = format_user_context(app_details, user_actions, pkt_offset_ms)

        tracker.reset()
        analyzer.analyze_packet(
            pid, pkt_info, tools,
            user_context=user_context,
            has_app_details=app_details is not None,
            has_user_actions=user_actions is not None,
        )

        if tracker.assigned:
            stats["classified"] += 1
            if tracker.created_description:
                logger.info("  -> Created & assigned event %d: %s", tracker.event_id, tracker.created_description)
            else:
                logger.info("  -> Assigned to event %d", tracker.event_id)
        else:
            stats["errors"] += 1
            logger.warning("  -> Could not classify packet %d", pid)

    logger.info("=" * 60)
    logger.info("Analysis Complete!")
    logger.info("  Total packets:  %d", stats["total"])
    logger.info("  Classified:     %d", stats["classified"])
    logger.info("  Errors/skipped: %d", stats["errors"])
    logger.info("=" * 60)


# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Analyze network packets and group them into application events using LLM + MCP"
    )

    parser.add_argument(
        "-r", "--recording-id", type=int, required=True,
        help="Recording ID to analyze",
    )

    # MCP server
    parser.add_argument(
        "--mcp-url", default="http://localhost:8765",
        help="MCP packet-db server URL (default: http://localhost:8765)",
    )

    # LLM
    parser.add_argument(
        "--model", default="qwen3:8b",
        help="Ollama model to use",
    )
    parser.add_argument(
        "--ollama-host", default="http://localhost:11434",
        help="Ollama server URL",
    )

    parser.add_argument(
        "--app-details", default=None,
        help="Path to app_details.txt describing the application and its behaviour",
    )
    parser.add_argument(
        "--user-intend", default=None,
        help="Path to user_intend.txt with timestamped user actions (MM:SS description)",
    )

    parser.add_argument(
        "-v", "--verbose", action="count", default=0,
        help="Increase verbosity (-v for DEBUG)",
    )

    args = parser.parse_args()

    if args.verbose >= 1:
        logging.getLogger().setLevel(logging.DEBUG)

    # Load optional context files
    app_details: Optional[str] = None
    user_actions: Optional[List[UserAction]] = None

    if args.app_details:
        app_details = load_app_details(args.app_details)
    if args.user_intend:
        user_actions = parse_intend_file(args.user_intend)

    mcp_client = MCPClient(base_url=args.mcp_url)

    analyzer = PacketAnalyzer(
        model=args.model,
        ollama_host=args.ollama_host,
    )

    try:
        analyzer.initialize()
        run_analysis(
            mcp_client, analyzer, args.recording_id,
            app_details=app_details,
            user_actions=user_actions,
        )
    except Exception as e:
        logger.error("Analysis failed: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
