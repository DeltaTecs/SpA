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
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

logger = logging.getLogger(__name__)
SENSITIVE_QUERY_KEYS = {"api_key", "apikey", "key", "token", "tavilyapikey"}


def _trace_mcp_calls() -> bool:
    """Return true only when per-call MCP debug logging is explicitly enabled."""
    return os.environ.get("MCP_TRACE_CALLS", "").lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class MCPToolSpec:
    name: str
    description: str
    input_schema: Dict[str, Any]


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
        self._endpoint = _mcp_endpoint(self.base_url)
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
                logger.info(
                    "MCP connected: session=%s",
                    self._session_id or "(stateless)",
                )

                # Remote MCP servers may be stateless and omit mcp-session-id.
                # Local FastMCP servers still return one, so include it when present.
                if self._session_id:
                    headers["Mcp-Session-Id"] = self._session_id
                notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
                self.session.post(self._endpoint, json=notif, headers=headers, timeout=5)
                return
                
            except requests.ConnectionError:
                if attempt % 5 == 0:
                    logger.info(
                        "Waiting for MCP server at %s ...",
                        redact_url(self.base_url),
                    )
            except Exception as e:
                logger.warning("MCP connection error (attempt %d): %s", attempt + 1, e)
            time.sleep(1)

        raise RuntimeError(f"MCP server not reachable at {redact_url(self.base_url)}")

    def _parse_sse_response(self, text: str) -> dict:
        """Parse SSE event stream and extract JSON-RPC result."""
        data_lines: list[str] = []
        for line in text.splitlines():
            if line.startswith("data:"):
                data_lines.append(line[5:].lstrip())
                continue
            if data_lines and line.strip():
                data_lines.append(line)
                continue
            if not line.strip() and data_lines:
                parsed = _parse_sse_data_lines(data_lines)
                if parsed is not None:
                    return parsed
                data_lines = []
        if data_lines:
            parsed = _parse_sse_data_lines(data_lines)
            if parsed is not None:
                return parsed
        raise RuntimeError(f"No JSON data in response: {text[:200]}")

    def request(
        self,
        method: str,
        params: Optional[Dict[str, Any]] = None,
        *,
        timeout: float = 30,
    ) -> dict:
        """Invoke one MCP JSON-RPC method and return the parsed response."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params or {},
        }

        resp = self.session.post(
            self._endpoint,
            json=payload,
            headers=headers,
            timeout=timeout,
        )
        if resp.status_code >= 400:
            raise RuntimeError(
                f"MCP request {method} failed ({resp.status_code}): {resp.text[:200]}"
            )

        data = self._parse_sse_response(resp.text)
        if "error" in data:
            raise RuntimeError(f"MCP error: {data['error']}")
        return data

    def list_tools(self, timeout: float = 30) -> list[MCPToolSpec]:
        """Return tool metadata advertised by the MCP server."""
        tools: list[MCPToolSpec] = []
        cursor: Optional[str] = None

        while True:
            params = {"cursor": cursor} if cursor else {}
            data = self.request("tools/list", params, timeout=timeout)
            result = data.get("result", data)
            if not isinstance(result, dict):
                raise RuntimeError(f"Unexpected tools/list result: {result}")

            for raw_tool in result.get("tools", []) or []:
                if not isinstance(raw_tool, dict):
                    continue
                tools.append(
                    MCPToolSpec(
                        name=str(raw_tool.get("name") or ""),
                        description=str(raw_tool.get("description") or ""),
                        input_schema=(
                            raw_tool.get("inputSchema")
                            or raw_tool.get("input_schema")
                            or {"type": "object", "properties": {}}
                        ),
                    )
                )

            cursor = result.get("nextCursor") or result.get("next_cursor")
            if not cursor:
                return [tool for tool in tools if tool.name]

    def call_tool(self, tool_name: str, arguments: Dict[str, Any], timeout: float = 30) -> str:
        """Invoke an MCP tool via JSON-RPC over HTTP and return the text result."""
        if _trace_mcp_calls():
            logger.debug("MCP tool call: %s(%s)", tool_name, arguments)

        data = self.request(
            "tools/call",
            {"name": tool_name, "arguments": arguments},
            timeout=timeout,
        )
        result = data.get("result", data)
        # MCP tool results are wrapped in {"content": [{"text": "..."}]}
        if isinstance(result, dict) and "content" in result:
            parts = result["content"]
            return "\n".join(
                p.get("text", str(p)) for p in parts if isinstance(p, dict)
            )
        return str(result)

    # ------------------------------------------------------------------
    # convenience wrappers
    # ------------------------------------------------------------------

    def list_packet_ids(self, recording_id: int) -> str:
        return self.call_tool("list_packet_ids", {"recording_id": recording_id})

    def events_for_recording(self, recording_id: int, packet_id: int = 0) -> str:
        return self.call_tool(
            "events_for_recording",
            {"recording_id": recording_id, "packet_id": packet_id},
        )

    def create_event_and_assign_packet(
        self,
        packet_id: int,
        description: str,
        reason: str = "",
        confidence: Optional[float] = None,
    ) -> str:
        """Create a new event and attach the packet atomically."""
        return self.call_tool(
            "create_event_and_assign_packet",
            {
                "packet_id": packet_id,
                "description": description,
                "reason": reason,
                "confidence": confidence,
            },
        )

    def assign_packet_to_event(
        self,
        packet_id: int,
        event_id: int,
        reason: str = "",
        confidence: Optional[float] = None,
    ) -> str:
        return self.call_tool(
            "assign_packet_to_event",
            {
                "packet_id": packet_id,
                "event_id": event_id,
                "reason": reason,
                "confidence": confidence,
            },
        )

    def update_event_description(self, event_id: int, description: str) -> str:
        return self.call_tool(
            "update_event_description",
            {"event_id": event_id, "description": description},
        )

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


def _mcp_endpoint(base_url: str) -> str:
    """Return the streamable-http MCP endpoint for a base URL or full endpoint."""

    parsed = urlsplit(base_url.rstrip("/"))
    path = parsed.path.rstrip("/")
    if path.endswith("/mcp"):
        endpoint_path = parsed.path if parsed.path.endswith("/") else path
        return urlunsplit(
            (parsed.scheme, parsed.netloc, endpoint_path, parsed.query, parsed.fragment)
        )

    endpoint_path = f"{path}/mcp" if path else "/mcp"
    return urlunsplit(
        (parsed.scheme, parsed.netloc, endpoint_path, parsed.query, parsed.fragment)
    )


def redact_url(url: str) -> str:
    """Hide credential-like query parameters before URLs reach logs."""

    parsed = urlsplit(url)
    if not parsed.query:
        return url

    query = [
        (key, "***" if key.lower() in SENSITIVE_QUERY_KEYS else value)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
    ]
    return urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urlencode(query), parsed.fragment)
    )


def _parse_sse_data_lines(data_lines: list[str]) -> Optional[dict]:
    """Parse JSON-RPC data from standard and Tavily-style SSE line framing."""

    for data in ("".join(data_lines).strip(), "\n".join(data_lines).strip()):
        if not data.startswith("{"):
            continue
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            continue
    return None
