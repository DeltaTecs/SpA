#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mcp_client.py

Thin HTTP wrapper around the MCP SSE server for calling MCP tools
exposed by the packet-db server.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, Optional

import requests

logger = logging.getLogger(__name__)


class MCPClient:
    """
    Call MCP tools exposed by the packet-db server over HTTP (streamable-http transport).
    
    The streamable-http protocol is simpler than SSE:
    1. POST /mcp with 'initialize' -> get session ID from response header
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

    def create_event(self, description: str) -> str:
        return self.call_tool("create_event", {"description": description})

    def assign_packet_to_event(self, packet_id: int, event_id: int) -> str:
        return self.call_tool("assign_packet_to_event", {"packet_id": packet_id, "event_id": event_id})

    def packet_info(self, packet_id: int) -> str:
        return self.call_tool("packet_info", {"packet_id": packet_id})

    def conversation_packets(
        self,
        conversation_id: int,
        packet_id: int = 0,
        before: int = 5,
        after: int = 5,
    ) -> str:
        return self.call_tool(
            "conversation_packets",
            {
                "conversation_id": conversation_id,
                "packet_id": packet_id,
                "before": before,
                "after": after,
            },
        )

    def packets_in_time_window(
        self,
        recording_id: int,
        start_ms: int,
        end_ms: int,
        max_packets: int = 40,
    ) -> str:
        return self.call_tool(
            "packets_in_time_window",
            {
                "recording_id": recording_id,
                "start_ms": start_ms,
                "end_ms": end_ms,
                "max_packets": max_packets,
            },
        )
