#!/opt/hexstrike-venv/bin/python
from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path

try:
    from mcp.server.fastmcp import FastMCP
    from mcp.server.fastmcp.server import TransportSecuritySettings
except ImportError as e:  # pragma: no cover
    raise RuntimeError("mcp package is required") from e


MCP_HOST = os.environ.get("HEXSTRIKE_BASH_MCP_HOST", "0.0.0.0")
MCP_PORT = int(os.environ.get("HEXSTRIKE_BASH_MCP_PORT", "8766"))
DEFAULT_CWD = os.environ.get("HEXSTRIKE_BASH_MCP_CWD", "/workspace")
DEFAULT_TIMEOUT_SECONDS = int(os.environ.get("HEXSTRIKE_BASH_MCP_TIMEOUT", "60"))
MAX_TIMEOUT_SECONDS = int(os.environ.get("HEXSTRIKE_BASH_MCP_MAX_TIMEOUT", "300"))
MAX_OUTPUT_BYTES = int(os.environ.get("HEXSTRIKE_BASH_MCP_MAX_OUTPUT_BYTES", "65536"))


mcp = FastMCP(
    "hexstrike-bash",
    host=MCP_HOST,
    port=MCP_PORT,
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=False
    ),
)


def _truncate(text: str, max_bytes: int) -> tuple[str, bool]:
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return text, False
    truncated = encoded[:max_bytes].decode("utf-8", errors="replace")
    return truncated, True


def _text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _working_dir(cwd: str) -> Path:
    path = Path(cwd).expanduser()
    if not path.is_absolute():
        path = Path(DEFAULT_CWD) / path
    return path


@mcp.tool()
def bash(command: str, cwd: str = DEFAULT_CWD, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS) -> str:
    """Run a Bash command inside the HexStrike container."""

    if not command or not command.strip():
        return "Refusing to run an empty command."

    timeout = max(1, min(int(timeout_seconds), MAX_TIMEOUT_SECONDS))
    working_dir = _working_dir(cwd)
    if not working_dir.exists() or not working_dir.is_dir():
        return f"Working directory does not exist or is not a directory: {cwd}"

    try:
        completed = subprocess.run(
            ["/bin/bash", "-lc", command],
            cwd=str(working_dir),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        stdout = _text(e.stdout)
        stderr = _text(e.stderr)
        stdout, stdout_truncated = _truncate(stdout, MAX_OUTPUT_BYTES)
        stderr, stderr_truncated = _truncate(stderr, MAX_OUTPUT_BYTES)
        parts = [
            f"Timed out after {timeout} seconds",
            f"cwd: {working_dir}",
            f"command: {command}",
            f"stdout{ ' (truncated)' if stdout_truncated else '' }:\n{stdout}",
            f"stderr{ ' (truncated)' if stderr_truncated else '' }:\n{stderr}",
        ]
        return "\n\n".join(parts)

    stdout, stdout_truncated = _truncate(_text(completed.stdout), MAX_OUTPUT_BYTES)
    stderr, stderr_truncated = _truncate(_text(completed.stderr), MAX_OUTPUT_BYTES)
    parts = [
        f"exit_code: {completed.returncode}",
        f"cwd: {working_dir}",
        f"command: {command}",
        f"stdout{ ' (truncated)' if stdout_truncated else '' }:\n{stdout}",
        f"stderr{ ' (truncated)' if stderr_truncated else '' }:\n{stderr}",
    ]
    return "\n\n".join(parts)


def main() -> None:
    transport = os.environ.get("HEXSTRIKE_BASH_MCP_TRANSPORT", "streamable-http").lower()
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    logging.getLogger(__name__).info(
        "Starting HexStrike Bash MCP server (transport=%s, host=%s, port=%d)",
        transport,
        MCP_HOST,
        MCP_PORT,
    )
    mcp.run(transport=transport)


if __name__ == "__main__":
    main()
