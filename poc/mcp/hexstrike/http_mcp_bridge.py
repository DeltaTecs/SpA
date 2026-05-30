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
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


PYTHON = os.environ.get("HEXSTRIKE_VENV_PYTHON", "/opt/hexstrike-venv/bin/python")
HEXSTRIKE_HOME = Path(os.environ.get("HEXSTRIKE_HOME", "/opt/hexstrike-ai"))
HEXSTRIKE_MCP_SCRIPT = HEXSTRIKE_HOME / "hexstrike_mcp.py"
HEXSTRIKE_SERVER_URL = os.environ.get("HEXSTRIKE_SERVER_URL", "http://127.0.0.1:8888")
MCP_HOST = os.environ.get("HEXSTRIKE_MCP_HTTP_HOST", "0.0.0.0")
MCP_PORT = int(os.environ.get("HEXSTRIKE_MCP_HTTP_PORT", "8767"))
TOOL_TIMEOUT_SECONDS = int(os.environ.get("HEXSTRIKE_MCP_HTTP_TIMEOUT", "900"))
PROCESS_API_TIMEOUT_SECONDS = float(os.environ.get("HEXSTRIKE_PROCESS_API_TIMEOUT", "5"))
MAX_PROCESS_STOP_WORKERS = int(os.environ.get("HEXSTRIKE_PROCESS_STOP_WORKERS", "8"))


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
                    "result": _stop_active_tools(),
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


class HexStrikeApiError(RuntimeError):
    """An unsuccessful request to the local HexStrike REST API."""

    def __init__(self, method: str, path: str, detail: str, *, status_code: int | None = None):
        status = f"HTTP {status_code}" if status_code is not None else "request failed"
        super().__init__(f"{method} {path} {status}: {detail}")
        self.status_code = status_code


def _stop_active_tools() -> dict[str, Any]:
    """Stop HexStrike-managed scanners and the stdio MCP wrappers waiting on them."""

    managed = _stop_hexstrike_managed_processes()
    stdio = _stop_active_stdio_tools()
    message = (
        f"Stopped {len(managed['stopped'])} HexStrike-managed process(es) and "
        f"{stdio['stopped']} active HexStrike MCP subprocess(es)."
    )
    if managed["already_finished"]:
        message += f" {len(managed['already_finished'])} managed process(es) had already exited."
    if managed["failed"]:
        message += f" Failed to stop {len(managed['failed'])} managed process(es)."
    if managed.get("discovery_error"):
        message += " Could not enumerate HexStrike-managed processes."
    return {
        "managed_processes": managed,
        "mcp_subprocesses": stdio,
        "message": message,
    }


def _stop_hexstrike_managed_processes() -> dict[str, Any]:
    """Terminate scanners tracked by HexStrike's process-management REST API."""

    result: dict[str, Any] = {
        "found": 0,
        "stopped": [],
        "already_finished": [],
        "failed": [],
    }
    try:
        pids = _list_hexstrike_managed_process_pids()
    except Exception as exc:  # noqa: BLE001 - stdio wrappers still need to be stopped
        logger.warning("Could not list HexStrike-managed processes: %s", exc)
        result["discovery_error"] = str(exc)
        return result

    result["found"] = len(pids)
    if not pids:
        return result

    worker_count = max(1, min(len(pids), MAX_PROCESS_STOP_WORKERS))
    with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="hexstrike-stop") as pool:
        futures = {pool.submit(_terminate_hexstrike_managed_process, pid): pid for pid in pids}
        for future in as_completed(futures):
            pid = futures[future]
            try:
                if future.result():
                    result["stopped"].append(pid)
                else:
                    result["already_finished"].append(pid)
            except Exception as exc:  # noqa: BLE001 - stop the other processes too
                logger.warning("Could not stop HexStrike-managed process %d: %s", pid, exc)
                result["failed"].append({"pid": pid, "error": str(exc)})

    result["stopped"].sort()
    result["already_finished"].sort()
    result["failed"].sort(key=lambda failure: failure["pid"])
    return result


def _list_hexstrike_managed_process_pids() -> list[int]:
    """Return active scanner PIDs, with a fallback for HexStrike v6 list responses.

    The pinned HexStrike v6 server's ``/api/processes/list`` response includes
    its internal ``Popen`` object while a scanner is active, which Flask cannot
    JSON-encode. Its dashboard endpoint exposes sanitized process records, so use
    that only when the documented list endpoint fails.
    """

    try:
        payload = _request_hexstrike_json("/api/processes/list")
        active = payload.get("active_processes")
        if not isinstance(active, dict):
            raise ValueError("response field 'active_processes' is not an object")
        return sorted({_parse_pid(pid) for pid in active})
    except Exception as exc:  # noqa: BLE001 - compatibility fallback for upstream v6
        logger.warning(
            "Could not read HexStrike process list (%s); falling back to dashboard",
            exc,
        )

    payload = _request_hexstrike_json("/api/processes/dashboard")
    processes = payload.get("processes")
    if not isinstance(processes, list):
        raise ValueError("dashboard response field 'processes' is not a list")
    return sorted(
        {
            _parse_pid(process.get("pid"))
            for process in processes
            if isinstance(process, dict)
        }
    )


def _parse_pid(value: Any) -> int:
    """Validate a PID returned by the HexStrike API."""

    if isinstance(value, bool):
        raise ValueError(f"invalid process id: {value!r}")
    try:
        pid = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid process id: {value!r}") from exc
    if pid <= 0:
        raise ValueError(f"invalid process id: {value!r}")
    return pid


def _terminate_hexstrike_managed_process(pid: int) -> bool:
    """Terminate one managed scanner. Return ``False`` if it already exited."""

    path = f"/api/processes/terminate/{pid}"
    try:
        payload = _request_hexstrike_json(path, method="POST")
    except HexStrikeApiError as exc:
        if exc.status_code == 404:
            return False
        raise
    if payload.get("success") is not True:
        raise HexStrikeApiError("POST", path, str(payload))
    return True


def _request_hexstrike_json(path: str, *, method: str = "GET") -> dict[str, Any]:
    """Call the local HexStrike REST API and decode an object response."""

    request = Request(
        f"{HEXSTRIKE_SERVER_URL.rstrip('/')}{path}",
        data=b"" if method == "POST" else None,
        headers={"Accept": "application/json"},
        method=method,
    )
    try:
        with urlopen(request, timeout=PROCESS_API_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace").strip()
        raise HexStrikeApiError(method, path, detail or exc.reason, status_code=exc.code) from exc
    except URLError as exc:
        raise HexStrikeApiError(method, path, str(exc.reason)) from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise HexStrikeApiError(method, path, str(exc)) from exc
    if not isinstance(payload, dict):
        raise HexStrikeApiError(method, path, "response is not a JSON object")
    return payload


def _stop_active_stdio_tools() -> dict[str, Any]:
    pids = _active_hexstrike_mcp_pids()
    if not pids:
        return {"stopped": 0, "message": "No active HexStrike MCP subprocess."}

    _terminate_processes(pids)
    return {"stopped": len(pids), "message": "Stop requested for active HexStrike MCP subprocesses."}


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
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            continue
        except OSError as exc:
            logger.warning("Could not signal HexStrike MCP subprocess %d: %s", pid, exc)

    _wait_for_exit(pids, timeout_seconds=5)
    remaining = [pid for pid in pids if (Path("/proc") / str(pid)).exists()]
    for pid in remaining:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            continue
        except OSError as exc:
            logger.warning("Could not kill HexStrike MCP subprocess %d: %s", pid, exc)


def _wait_for_exit(pids: list[int], *, timeout_seconds: float) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if all(not (Path("/proc") / str(pid)).exists() for pid in pids):
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
