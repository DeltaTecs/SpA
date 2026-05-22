#!/usr/bin/env python3
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
    log_level = os.environ.get("LOG_LEVEL", "").strip().lower()
    return (
        log_level == "verbose"
        or os.environ.get("MCP_TRACE_CALLS", "").lower() in {"1", "true", "yes", "on"}
    )


def _log_payload(value: Any) -> str:
    try:
        text = json.dumps(value, indent=2, sort_keys=True, default=str)
    except TypeError:
        text = str(value)

    max_chars = int(os.environ.get("MCP_LOG_MAX_CHARS", "20000"))
    if len(text) <= max_chars:
        return text
    return f"{text[:max_chars]}\n... truncated {len(text) - max_chars} chars"


@dataclass(frozen=True)
class MCPToolSpec:
    name: str
    description: str
    input_schema: Dict[str, Any]


class MCPClient:
    """Call streamable-http MCP tools over JSON-RPC."""

    def __init__(
        self,
        base_url: str,
        *,
        connect_timeout: float = 10,
        default_timeout: float = 30,
        connect_attempts: int = 30,
    ):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self._session_id: Optional[str] = None
        self._endpoint = _mcp_endpoint(self.base_url)
        self._connect_timeout = connect_timeout
        self._default_timeout = default_timeout
        self._connect_attempts = max(1, int(connect_attempts))
        self._connect()

    def _connect(self) -> None:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }

        for attempt in range(self._connect_attempts):
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
                    self._endpoint,
                    json=init_payload,
                    headers=headers,
                    timeout=self._connect_timeout,
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
                self.session.post(
                    self._endpoint,
                    json=notif,
                    headers=headers,
                    timeout=min(self._connect_timeout, 5),
                )
                return
            except requests.ConnectionError:
                if attempt % 5 == 0:
                    logger.info("Waiting for MCP server at %s ...", redact_url(self.base_url))
            except Exception as exc:
                logger.warning("MCP connection error (attempt %d): %s", attempt + 1, exc)
            time.sleep(1)

        raise RuntimeError(f"MCP server not reachable at {redact_url(self.base_url)}")

    def _parse_sse_response(self, text: str) -> dict:
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
        timeout: Optional[float] = None,
    ) -> dict:
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
            timeout=timeout or self._default_timeout,
        )
        if resp.status_code >= 400:
            raise RuntimeError(
                f"MCP request {method} failed ({resp.status_code}): {resp.text[:200]}"
            )

        data = self._parse_sse_response(resp.text)
        if "error" in data:
            raise RuntimeError(f"MCP error: {data['error']}")
        return data

    def list_tools(self, timeout: Optional[float] = None) -> list[MCPToolSpec]:
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

    def call_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        timeout: Optional[float] = None,
    ) -> str:
        if _trace_mcp_calls():
            logger.debug(
                "MCP call input base_url=%s tool=%s arguments=%s",
                redact_url(self.base_url),
                tool_name,
                _log_payload(arguments),
            )

        data = self.request(
            "tools/call",
            {"name": tool_name, "arguments": arguments},
            timeout=timeout,
        )

        result = data.get("result", data)
        if isinstance(result, dict) and "content" in result:
            output = "\n".join(
                part.get("text", str(part))
                for part in result["content"]
                if isinstance(part, dict)
            )
        else:
            output = str(result)

        if _trace_mcp_calls():
            logger.debug(
                "MCP call output base_url=%s tool=%s output=%s",
                redact_url(self.base_url),
                tool_name,
                _log_payload(output),
            )
        return output

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
    """Hide credential-like query parameters before URLs reach logs or UI state."""

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
