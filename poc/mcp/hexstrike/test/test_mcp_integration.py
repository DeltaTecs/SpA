from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import tempfile
import time
import unittest
import uuid
from datetime import timedelta
from pathlib import Path
from typing import Any

import requests
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
try:
    from mcp.client.streamable_http import streamable_http_client
except ImportError:  # pragma: no cover - older mcp package compatibility
    from mcp.client.streamable_http import streamablehttp_client as streamable_http_client


PYTHON = os.environ.get("HEXSTRIKE_VENV_PYTHON", "/opt/hexstrike-venv/bin/python")
HEXSTRIKE_HOME = Path(os.environ.get("HEXSTRIKE_HOME", "/opt/hexstrike-ai"))
BASH_MCP_SCRIPT = Path("/usr/local/bin/hexstrike-bash-mcp")
HEXSTRIKE_MCP_SCRIPT = HEXSTRIKE_HOME / "hexstrike_mcp.py"
HEXSTRIKE_SERVER_SCRIPT = HEXSTRIKE_HOME / "hexstrike_server.py"
HEXSTRIKE_FILE_ROOT = Path("/tmp/hexstrike_files")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_tcp(host: str, port: int, timeout_seconds: float = 20) -> None:
    deadline = time.time() + timeout_seconds
    last_error: Exception | None = None

    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return
        except OSError as exc:
            last_error = exc
            time.sleep(0.2)

    raise RuntimeError(f"Timed out waiting for {host}:{port}: {last_error}")


def _wait_for_json(url: str, timeout_seconds: float = 60) -> dict[str, Any]:
    deadline = time.time() + timeout_seconds
    last_error: Exception | None = None

    while time.time() < deadline:
        try:
            response = requests.get(url, timeout=3)
            if response.status_code == 200:
                return response.json()
            last_error = RuntimeError(f"HTTP {response.status_code}: {response.text[:200]}")
        except (requests.RequestException, ValueError) as exc:
            last_error = exc
        time.sleep(0.5)

    raise RuntimeError(f"Timed out waiting for JSON response from {url}: {last_error}")


def _terminate_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return

    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def _content_text(result: Any) -> str:
    chunks: list[str] = []
    for item in getattr(result, "content", []) or []:
        text = getattr(item, "text", None)
        chunks.append(text if text is not None else str(item))
    return "\n".join(chunks)


def _structured_payload(result: Any) -> Any:
    for attr in ("structuredContent", "structured_content"):
        payload = getattr(result, attr, None)
        if payload is not None:
            return _unwrap_tool_payload(payload)

    text = _content_text(result).strip()
    if not text:
        return None

    try:
        return _unwrap_tool_payload(json.loads(text))
    except json.JSONDecodeError:
        return None


def _unwrap_tool_payload(payload: Any) -> Any:
    if isinstance(payload, dict) and set(payload) == {"result"}:
        return payload["result"]
    return payload


def _result_text(result: Any) -> str:
    payload = _structured_payload(result)
    if payload is not None:
        if isinstance(payload, str):
            return payload
        return json.dumps(payload, sort_keys=True)
    return _content_text(result)


def _assert_success(test_case: unittest.TestCase, result: Any) -> None:
    payload = _structured_payload(result)
    if isinstance(payload, dict):
        test_case.assertIs(payload.get("success"), True, payload)
        return

    text = _result_text(result).lower()
    test_case.assertRegex(text, r'["\']success["\']\s*:\s*true')


def _open_streamable_client(base_url: str) -> Any:
    try:
        return streamable_http_client(f"{base_url}/mcp", timeout=10)
    except TypeError as exc:
        if "timeout" not in str(exc):
            raise
        return streamable_http_client(f"{base_url}/mcp")


async def _list_streamable_tools(base_url: str) -> list[str]:
    async with _open_streamable_client(base_url) as (
        read_stream,
        write_stream,
        _get_session_id,
    ):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            tools = await session.list_tools()
            return [tool.name for tool in tools.tools]


async def _call_streamable_tool(base_url: str, name: str, arguments: dict[str, Any]) -> Any:
    async with _open_streamable_client(base_url) as (
        read_stream,
        write_stream,
        _get_session_id,
    ):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            return await session.call_tool(
                name,
                arguments,
                read_timeout_seconds=timedelta(seconds=10),
            )


async def _exercise_hexstrike_stdio_tools(server_url: str, token: str) -> dict[str, Any]:
    params = StdioServerParameters(
        command=PYTHON,
        args=[str(HEXSTRIKE_MCP_SCRIPT), "--server", server_url, "--timeout", "20"],
        cwd=str(HEXSTRIKE_HOME),
        env={
            **os.environ,
            "PYTHONUNBUFFERED": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
    )

    filename = f"mcp-tests/{token}.txt"
    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            tools = await session.list_tools()
            tool_names = [tool.name for tool in tools.tools]

            create_result = await session.call_tool(
                "create_file",
                {
                    "filename": filename,
                    "content": f"created:{token}",
                    "binary": False,
                },
                read_timeout_seconds=timedelta(seconds=20),
            )
            modify_result = await session.call_tool(
                "modify_file",
                {
                    "filename": filename,
                    "content": f"\nmodified:{token}",
                    "append": True,
                },
                read_timeout_seconds=timedelta(seconds=20),
            )
            list_result = await session.call_tool(
                "list_files",
                {"directory": "mcp-tests"},
                read_timeout_seconds=timedelta(seconds=20),
            )
            cache_result = await session.call_tool(
                "get_cache_stats",
                {},
                read_timeout_seconds=timedelta(seconds=20),
            )

    return {
        "filename": filename,
        "tool_names": tool_names,
        "create": create_result,
        "modify": modify_result,
        "list": list_result,
        "cache": cache_result,
    }


class HexStrikeProcessTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory(prefix="hexstrike-mcp-test-")
        self.addCleanup(self._tmpdir.cleanup)
        self.log_dir = Path(self._tmpdir.name)
        self._processes: list[subprocess.Popen[str]] = []

    def tearDown(self) -> None:
        for process in reversed(self._processes):
            _terminate_process(process)

    def _start_process(
        self,
        args: list[str],
        *,
        cwd: Path | str | None = None,
        env: dict[str, str] | None = None,
        log_name: str,
    ) -> subprocess.Popen[str]:
        log_file = open(self.log_dir / log_name, "w", encoding="utf-8")
        self.addCleanup(log_file.close)
        process = subprocess.Popen(
            args,
            cwd=str(cwd) if cwd is not None else None,
            env={**os.environ, **(env or {})},
            stdout=log_file,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self._processes.append(process)
        return process


class TestHexStrikeBashMcp(HexStrikeProcessTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.port = _free_port()
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.process = self._start_process(
            [PYTHON, str(BASH_MCP_SCRIPT)],
            env={
                "HEXSTRIKE_BASH_MCP_HOST": "127.0.0.1",
                "HEXSTRIKE_BASH_MCP_PORT": str(self.port),
                "HEXSTRIKE_BASH_MCP_CWD": "/workspace",
            },
            log_name="bash-mcp.log",
        )
        _wait_for_tcp("127.0.0.1", self.port)
        self.assertIsNone(self.process.poll(), "bash MCP process exited early")

    def test_bash_tool_executes_command_through_mcp(self) -> None:
        tool_names = asyncio.run(_list_streamable_tools(self.base_url))
        self.assertIn("bash", tool_names)

        result = asyncio.run(
            _call_streamable_tool(
                self.base_url,
                "bash",
                {
                    "command": "printf 'hexstrike-bash-ok\\n'; pwd",
                    "cwd": "/workspace",
                    "timeout_seconds": 5,
                },
            )
        )
        text = _result_text(result)

        self.assertIn("exit_code: 0", text)
        self.assertIn("cwd: /workspace", text)
        self.assertIn("stdout:\nhexstrike-bash-ok", text)
        self.assertIn("/workspace", text)

    def test_bash_tool_reports_invalid_working_directory(self) -> None:
        missing_dir = f"/tmp/does-not-exist-{uuid.uuid4().hex}"

        result = asyncio.run(
            _call_streamable_tool(
                self.base_url,
                "bash",
                {
                    "command": "pwd",
                    "cwd": missing_dir,
                    "timeout_seconds": 5,
                },
            )
        )
        text = _result_text(result)

        self.assertIn("Working directory does not exist or is not a directory", text)
        self.assertIn(missing_dir, text)


class TestHexStrikeMcpTools(HexStrikeProcessTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.port = _free_port()
        self.server_url = f"http://127.0.0.1:{self.port}"
        self.server_process = self._start_process(
            [PYTHON, str(HEXSTRIKE_SERVER_SCRIPT), "--port", str(self.port)],
            cwd=HEXSTRIKE_HOME,
            env={
                "HEXSTRIKE_PORT": str(self.port),
                "PYTHONUNBUFFERED": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            log_name="hexstrike-server.log",
        )
        _wait_for_json(f"{self.server_url}/api/cache/stats")
        self.assertIsNone(self.server_process.poll(), "HexStrike server exited early")

    def test_file_and_cache_tools_work_through_mcp_stdio(self) -> None:
        token = uuid.uuid4().hex
        results = asyncio.run(_exercise_hexstrike_stdio_tools(self.server_url, token))
        created_file = HEXSTRIKE_FILE_ROOT / results["filename"]
        self.addCleanup(lambda: created_file.unlink(missing_ok=True))

        for tool_name in ("create_file", "modify_file", "list_files", "get_cache_stats"):
            self.assertIn(tool_name, results["tool_names"])

        _assert_success(self, results["create"])
        _assert_success(self, results["modify"])

        self.assertTrue(created_file.exists(), f"Expected {created_file} to exist")
        self.assertEqual(f"created:{token}\nmodified:{token}", created_file.read_text())

        listing_text = _result_text(results["list"])
        self.assertIn(f"{token}.txt", listing_text)
        self.assertIn("file", listing_text)

        cache_payload = _structured_payload(results["cache"])
        if isinstance(cache_payload, dict):
            self.assertIn("size", cache_payload)
            self.assertIn("hit_rate", cache_payload)
        else:
            cache_text = _result_text(results["cache"])
            self.assertIn("hit_rate", cache_text)
            self.assertIn("size", cache_text)


if __name__ == "__main__":
    unittest.main()
