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
import json
import logging
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import requests

try:
    from langchain_ollama import ChatOllama
    from langchain_core.messages import HumanMessage, SystemMessage, AIMessage, ToolMessage
    from langchain_core.tools import tool as langchain_tool
except ImportError:
    raise ImportError(
        "langchain packages are required. "
        "Install with: pip install langchain langchain-ollama langchain-community"
    )

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
# MCP Client -- thin HTTP wrapper around the MCP SSE server
# ============================================================================

class MCPClient:
    """
    Call MCP tools exposed by the packet-db server over HTTP (streamable-http transport).
    
    The streamable-http protocol is simpler than SSE:
    1. POST /mcp with 'initialize' → get session ID from response header
    2. POST /mcp with session ID header for all subsequent requests
    3. Responses come as SSE events in the response body (synchronous)
    """

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self._session_id: Optional[str] = None
        self._endpoint = f"{self.base_url}/mcp"
        self._connect()

    # ------------------------------------------------------------------
    # low-level helpers
    # ------------------------------------------------------------------

    def _connect(self):
        """Initialize MCP session."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        
        for attempt in range(30):
            try:
                # Send initialize request
                init_payload = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "packet-analyzer", "version": "1.0"},
                    },
                }
                resp = self.session.post(
                    self._endpoint, json=init_payload, headers=headers, timeout=10
                )
                if resp.status_code != 200:
                    raise RuntimeError(f"Initialize failed: {resp.status_code}")
                
                self._session_id = resp.headers.get("mcp-session-id")
                if not self._session_id:
                    raise RuntimeError("No session ID in response")
                
                logger.info("MCP connected: session=%s", self._session_id)
                
                # Send initialized notification
                headers["Mcp-Session-Id"] = self._session_id
                notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
                self.session.post(self._endpoint, json=notif, headers=headers, timeout=5)
                return
                
            except requests.ConnectionError:
                if attempt % 5 == 0:
                    logger.info("Waiting for MCP server at %s ...", self.base_url)
            except Exception as e:
                logger.warning("MCP connection error (attempt %d): %s", attempt + 1, e)
            time.sleep(1)

        raise RuntimeError(f"MCP server not reachable at {self.base_url}")

    def _parse_sse_response(self, text: str) -> dict:
        """Parse SSE event stream and extract JSON-RPC result."""
        for line in text.splitlines():
            if line.startswith("data:"):
                data = line[5:].strip()
                if data.startswith("{"):
                    return json.loads(data)
        raise RuntimeError(f"No JSON data in response: {text[:200]}")

    def call_tool(self, tool_name: str, arguments: Dict[str, Any], timeout: float = 30) -> str:
        """Invoke an MCP tool via JSON-RPC over HTTP and return the text result."""
        if not self._session_id:
            raise RuntimeError("MCP client not connected")

        logger.debug("MCP tool call: %s(%s)", tool_name, arguments)

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Mcp-Session-Id": self._session_id,
        }
        
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments,
            },
        }

        resp = self.session.post(self._endpoint, json=payload, headers=headers, timeout=timeout)
        if resp.status_code >= 400:
            raise RuntimeError(
                f"MCP tool call failed ({resp.status_code}): {resp.text[:200]}"
            )

        data = self._parse_sse_response(resp.text)
        
        if "error" in data:
            raise RuntimeError(f"MCP error: {data['error']}")

        result = data.get("result", data)
        # MCP tool results are wrapped in {"content": [{"text": "..."}]}
        if isinstance(result, dict) and "content" in result:
            parts = result["content"]
            return "\n".join(
                p.get("text", str(p)) for p in parts if isinstance(p, dict)
            )
        return str(result)

    # ------------------------------------------------------------------
    # convenience wrappers (used by orchestrator, NOT by the LLM)
    # ------------------------------------------------------------------

    def list_packet_ids(self, recording_id: int) -> str:
        return self.call_tool("list_packet_ids", {"recording_id": recording_id})

    def events_for_recording(self, recording_id: int) -> str:
        return self.call_tool("events_for_recording", {"recording_id": recording_id})

    def create_event(self, description: str, timestamp: int) -> str:
        return self.call_tool("create_event", {"description": description, "timestamp": timestamp})

    def assign_packet_to_event(self, packet_id: int, event_id: int) -> str:
        return self.call_tool("assign_packet_to_event", {"packet_id": packet_id, "event_id": event_id})

    def packet_info(self, packet_id: int) -> str:
        return self.call_tool("packet_info", {"packet_id": packet_id})


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
    def get_surrounding_packet_ids(packet_id: int, window: int = 5) -> str:
        """Return the IDs of packets around the given packet_id (up to
        *window* packets before and after).  This lets you examine
        neighbouring traffic in the same recording to better understand
        the context of the current packet (e.g. a request followed by
        its response)."""
        try:
            idx = packet_ids.index(packet_id)
        except ValueError:
            return f"packet_id {packet_id} not in current recording"

        start = max(0, idx - window)
        end = min(len(packet_ids), idx + window + 1)
        neighbours = packet_ids[start:end]
        lines = [f"Packets around packet_id {packet_id} (window={window}):"]
        for pid in neighbours:
            marker = " <-- current" if pid == packet_id else ""
            lines.append(f"  packet_id:{pid}{marker}")
        return "\n".join(lines)

    @langchain_tool
    def get_events(recording_id_unused: int = 0) -> str:
        """Return all events that currently exist for this recording.
        Each event has an event_id and a short description.
        Use this before deciding whether to create a new event or assign
        the packet to an existing one."""
        return mcp.events_for_recording(recording_id)

    @langchain_tool
    def create_new_event(description: str, timestamp: int) -> str:
        """Create a brand-new event.
        Provide a short, descriptive label (e.g. 'TLS handshake',
        'User login request/response') and the packet timestamp.
        Returns the new event_id."""
        result = mcp.create_event(description, timestamp)
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
        get_surrounding_packet_ids,
        get_events,
        create_new_event,
        assign_to_event,
    ]
    return tools, tracker


# ============================================================================
# Packet Analyzer -- orchestrates the LLM tool-calling loop
# ============================================================================

SYSTEM_PROMPT = """\
You are a network traffic analyst.  Your job is to classify network packets
into application-level events (e.g. "Login request/response", "File upload", "API call -- /users").

You have the following tools at your disposal:

* **get_packet_info(packet_id)** -- get flow info, protocol layers,
  HTTP headers, and a 256-byte payload preview for ANY packet.
* **get_full_payload(packet_id)** -- get the COMPLETE cleartext payload
  when the 256-byte preview is not enough.
* **get_surrounding_packet_ids(packet_id, window)** -- discover nearby
  packet IDs so you can inspect preceding/following packets for context
  (e.g. request <-> response pairs).
* **get_events()** -- list all events that exist so far for this recording.
* **create_new_event(description, timestamp)** -- create a new event.
  Returns the event_id.
* **assign_to_event(packet_id, event_id)** -- assign the current packet
  to an event and adjust the event time range.

**Workflow for each packet you are given:**
1. You will receive the packet_id and basic info. Study it.
2. If you need more context, call get_surrounding_packet_ids and/or
   get_packet_info on neighbours, or get_full_payload.
3. Call get_events() to see existing events.
4. Decide: does this packet belong to an existing event, or should a new
   one be created?
5. Either call assign_to_event OR call create_new_event followed by
   assign_to_event. When creating an event, be as specific as possible but concise. Do not label events 'HTTP request', instead describe what purpose the request serves if possible.

Important:
- Always end with an assign_to_event call so the packet is persisted.
- You may call multiple tools before deciding.
- Investigate atleast 5 packets around the current packet for better context. Do so by using get_packet_info with an incremented or decremented packet_id.
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

    def analyze_packet(
        self,
        packet_id: int,
        packet_info_text: str,
        tools: list,
        *,
        max_rounds: int = 10,
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

        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(
                content=(
                    f"Classify the following packet (packet_id={packet_id}).\n\n"
                    f"{packet_info_text}\n\n"
                    "Use the tools to inspect surrounding packets or retrieve "
                    "full payloads if you need more context. Then assign the "
                    "packet to an existing or new event."
                )
            ),
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
):
    """Iterate over all packets in a recording, asking the LLM to classify each."""
    logger.info("Starting analysis for recording %d", recording_id)

    # Fetch ordered packet IDs from MCP
    raw = mcp_client.list_packet_ids(recording_id)
    logger.debug("list_packet_ids response:\n%s", raw)

    packet_ids: List[int] = []
    for line in raw.splitlines():
        m = re.search(r"packet_id:(\d+)", line)
        if m:
            packet_ids.append(int(m.group(1)))

    if not packet_ids:
        logger.warning("No packets found for recording %d", recording_id)
        return

    logger.info("Found %d packets for recording %d", len(packet_ids), recording_id)

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

        tracker.reset()
        analyzer.analyze_packet(pid, pkt_info, tools)

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
        "-v", "--verbose", action="count", default=0,
        help="Increase verbosity (-v for DEBUG)",
    )

    args = parser.parse_args()

    if args.verbose >= 1:
        logging.getLogger().setLevel(logging.DEBUG)

    mcp_client = MCPClient(base_url=args.mcp_url)

    analyzer = PacketAnalyzer(
        model=args.model,
        ollama_host=args.ollama_host,
    )

    try:
        analyzer.initialize()
        run_analysis(mcp_client, analyzer, args.recording_id)
    except Exception as e:
        logger.error("Analysis failed: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
