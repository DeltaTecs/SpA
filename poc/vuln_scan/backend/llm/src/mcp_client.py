#!/usr/bin/env python3
from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, Optional

import requests


logger = logging.getLogger(__name__)


def _trace_mcp_calls() -> bool:
    return os.environ.get("MCP_TRACE_CALLS", "").lower() in {"1", "true", "yes", "on"}


class MCPClient:
    """Call streamable-http MCP tools over JSON-RPC."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self._session_id: Optional[str] = None
        self._endpoint = f"{self.base_url}/mcp"
        self._connect()

    def _connect(self) -> None:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }

        for attempt in range(30):
            try:
                init_payload = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "vuln-scanner", "version": "1.0"},
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

                headers["Mcp-Session-Id"] = self._session_id
                notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
                self.session.post(self._endpoint, json=notif, headers=headers, timeout=5)
                return
            except requests.ConnectionError:
                if attempt % 5 == 0:
                    logger.info("Waiting for MCP server at %s ...", self.base_url)
            except Exception as exc:
                logger.warning("MCP connection error (attempt %d): %s", attempt + 1, exc)
            time.sleep(1)

        raise RuntimeError(f"MCP server not reachable at {self.base_url}")

    def _parse_sse_response(self, text: str) -> dict:
        for line in text.splitlines():
            if line.startswith("data:"):
                data = line[5:].strip()
                if data.startswith("{"):
                    return json.loads(data)
        raise RuntimeError(f"No JSON data in response: {text[:200]}")

    def call_tool(self, tool_name: str, arguments: Dict[str, Any], timeout: float = 30) -> str:
        if not self._session_id:
            raise RuntimeError("MCP client not connected")

        if _trace_mcp_calls():
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
            "params": {"name": tool_name, "arguments": arguments},
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
        if isinstance(result, dict) and "content" in result:
            return "\n".join(
                part.get("text", str(part))
                for part in result["content"]
                if isinstance(part, dict)
            )
        return str(result)

    def event_packets(self, event_id: int) -> str:
        return self.call_tool("event_packets", {"event_id": event_id})

    def events(self) -> str:
        return self.call_tool("events", {})

    def packet_info(self, packet_id: int) -> str:
        return self.call_tool("packet_info", {"packet_id": packet_id})

    def packet_payload_hexdump(self, packet_id: int) -> str:
        return self.call_tool("packet_payload_hexdump", {"packet_id": packet_id})

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
