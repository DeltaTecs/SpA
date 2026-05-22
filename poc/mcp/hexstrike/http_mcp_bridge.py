#!/opt/hexstrike-venv/bin/python
from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
import time
import uuid
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


PYTHON = os.environ.get("HEXSTRIKE_VENV_PYTHON", "/opt/hexstrike-venv/bin/python")
HEXSTRIKE_HOME = Path(os.environ.get("HEXSTRIKE_HOME", "/opt/hexstrike-ai"))
HEXSTRIKE_MCP_SCRIPT = HEXSTRIKE_HOME / "hexstrike_mcp.py"
HEXSTRIKE_SERVER_URL = os.environ.get("HEXSTRIKE_SERVER_URL", "http://127.0.0.1:8888")
MCP_HOST = os.environ.get("HEXSTRIKE_MCP_HTTP_HOST", "0.0.0.0")
MCP_PORT = int(os.environ.get("HEXSTRIKE_MCP_HTTP_PORT", "8767"))
TOOL_TIMEOUT_SECONDS = int(os.environ.get("HEXSTRIKE_MCP_HTTP_TIMEOUT", "900"))


logger = logging.getLogger(__name__)


def _log_level() -> int:
    normalized = os.environ.get("LOG_LEVEL", "INFO").strip().upper()
    if normalized == "VERBOSE":
        return logging.DEBUG
    return getattr(logging, normalized, logging.INFO)


def _log_payload(value: Any) -> str:
    try:
        text = json.dumps(value, indent=2, sort_keys=True, default=str)
    except TypeError:
        text = str(value)

    max_chars = int(os.environ.get("MCP_LOG_MAX_CHARS", "20000"))
    if len(text) <= max_chars:
        return text
    return f"{text[:max_chars]}\n... truncated {len(text) - max_chars} chars"


def _stdio_params() -> StdioServerParameters:
    return StdioServerParameters(
        command=PYTHON,
        args=[
            str(HEXSTRIKE_MCP_SCRIPT),
            "--server",
            HEXSTRIKE_SERVER_URL,
            "--timeout",
            str(TOOL_TIMEOUT_SECONDS),
        ],
        cwd=str(HEXSTRIKE_HOME),
        env={
            **os.environ,
            "PYTHONUNBUFFERED": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
    )


async def _list_tools() -> dict[str, Any]:
    async with stdio_client(_stdio_params()) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            tools = await session.list_tools()
            return _to_jsonable(tools)


async def _call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    async with stdio_client(_stdio_params()) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            result = await session.call_tool(
                name,
                arguments,
                read_timeout_seconds=timedelta(seconds=TOOL_TIMEOUT_SECONDS),
            )
            return _to_jsonable(result)


def _to_jsonable(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    if isinstance(value, dict):
        return {key: _to_jsonable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_to_jsonable(item) for item in value]
    return value


class BridgeHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:
        if self.path.rstrip("/") != "/mcp":
            self.send_error(404)
            return

        try:
            payload = self._read_json()
            method = payload.get("method")
            request_id = payload.get("id")

            if method == "initialize":
                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {"listChanged": False}},
                        "serverInfo": {
                            "name": "hexstrike-http-mcp-bridge",
                            "version": "1.0",
                        },
                    },
                }
            elif method == "notifications/initialized":
                response = {"jsonrpc": "2.0", "id": request_id, "result": {}}
            elif method == "tools/list":
                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": asyncio.run(_list_tools()),
                }
            elif method == "tools/call":
                params = payload.get("params") or {}
                tool_name = str(params.get("name") or "")
                tool_arguments = params.get("arguments") or {}
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(
                        "MCP tool input name=%s arguments=%s",
                        tool_name,
                        _log_payload(tool_arguments),
                    )
                result = asyncio.run(_call_tool(tool_name, tool_arguments))
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(
                        "MCP tool output name=%s output=%s",
                        tool_name,
                        _log_payload(result),
                    )
                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": result,
                }
            elif method == "tools/stop":
                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": _stop_active_stdio_tools(),
                }
            else:
                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32601, "message": f"Unknown method: {method}"},
                }
        except Exception as exc:
            logger.exception("HexStrike MCP bridge request failed")
            response = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32000, "message": str(exc)},
            }

        self._send_sse(response)

    def log_message(self, fmt: str, *args: Any) -> None:
        logger.info("%s - %s", self.address_string(), fmt % args)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or "0")
        raw = self.rfile.read(length)
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))

    def _send_sse(self, payload: dict[str, Any]) -> None:
        body = f"event: message\ndata: {json.dumps(payload)}\n\n".encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Mcp-Session-Id", self.headers.get("Mcp-Session-Id") or uuid.uuid4().hex)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _stop_active_stdio_tools() -> dict[str, Any]:
    pids = _active_hexstrike_tool_pids()
    if not pids:
        return {"stopped": 0, "message": "No active HexStrike MCP tool process."}

    _terminate_processes(pids)
    return {"stopped": len(pids), "message": "Stop requested for active HexStrike MCP tool processes."}


def _active_hexstrike_tool_pids() -> list[int]:
    active: set[int] = set(_active_hexstrike_mcp_pids())
    for backend_pid in _active_hexstrike_backend_pids():
        active.update(_descendant_pids(backend_pid))
    return sorted(active)


def _active_hexstrike_mcp_pids() -> list[int]:
    current_pid = os.getpid()
    descendants = _descendant_pids(current_pid)
    active: list[int] = []
    script_name = HEXSTRIKE_MCP_SCRIPT.name
    script_path = str(HEXSTRIKE_MCP_SCRIPT)
    for pid in descendants:
        cmdline = _cmdline(pid)
        if script_path in cmdline or script_name in cmdline:
            active.append(pid)
    return active


def _active_hexstrike_backend_pids() -> list[int]:
    current_pid = os.getpid()
    descendants = _descendant_pids(current_pid)
    active: list[int] = []
    for pid in descendants:
        cmdline = _cmdline(pid)
        if "hexstrike_server.py" in cmdline:
            active.append(pid)
    return active


def _descendant_pids(root_pid: int) -> set[int]:
    children: dict[int, list[int]] = {}
    proc_root = Path("/proc")
    if not proc_root.exists():
        return set()

    for stat_path in proc_root.glob("[0-9]*/stat"):
        try:
            pid = int(stat_path.parent.name)
            stat = stat_path.read_text(encoding="utf-8", errors="replace")
            closing_paren = stat.rfind(")")
            fields = stat[closing_paren + 2 :].split()
            ppid = int(fields[1])
        except (OSError, ValueError, IndexError):
            continue
        children.setdefault(ppid, []).append(pid)

    descendants: set[int] = set()
    stack = list(children.get(root_pid, []))
    while stack:
        pid = stack.pop()
        if pid in descendants:
            continue
        descendants.add(pid)
        stack.extend(children.get(pid, []))
    return descendants


def _cmdline(pid: int) -> str:
    try:
        raw = (Path("/proc") / str(pid) / "cmdline").read_bytes()
    except OSError:
        return ""
    return raw.replace(b"\x00", b" ").decode("utf-8", errors="replace")


def _terminate_processes(pids: list[int]) -> None:
    targets = _process_tree_pids(pids)
    for pid in targets:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            continue
        except OSError as exc:
            logger.warning("Could not signal HexStrike MCP subprocess %d: %s", pid, exc)

    _wait_for_exit(targets, timeout_seconds=5)
    remaining = [pid for pid in targets if _pid_exists(pid)]
    for pid in remaining:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            continue
        except OSError as exc:
            logger.warning("Could not kill HexStrike MCP subprocess %d: %s", pid, exc)

    _wait_for_exit(remaining, timeout_seconds=2)


def _process_tree_pids(root_pids: list[int]) -> list[int]:
    targets: set[int] = set()
    for pid in root_pids:
        targets.add(pid)
        targets.update(_descendant_pids(pid))
    return sorted(targets, reverse=True)


def _pid_exists(pid: int) -> bool:
    return (Path("/proc") / str(pid)).exists()


def _wait_for_exit(pids: list[int], *, timeout_seconds: float) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if all(not _pid_exists(pid) for pid in pids):
            return
        time.sleep(0.1)


def main() -> None:
    log_level = _log_level()
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        stream=sys.stdout,
        force=True,
    )
    logging.getLogger().setLevel(log_level)
    logger.info(
        "Starting HexStrike HTTP MCP bridge on %s:%d for %s",
        MCP_HOST,
        MCP_PORT,
        HEXSTRIKE_SERVER_URL,
    )
    ThreadingHTTPServer((MCP_HOST, MCP_PORT), BridgeHandler).serve_forever()


if __name__ == "__main__":
    main()
