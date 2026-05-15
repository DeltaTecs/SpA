#!/opt/hexstrike-venv/bin/python
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
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
logger = logging.getLogger(__name__)


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


def _log_level() -> int:
    normalized = os.environ.get("LOG_LEVEL", "INFO").strip().upper()
    if normalized == "VERBOSE":
        return logging.DEBUG
    return getattr(logging, normalized, logging.INFO)


def _log_payload(value: object) -> str:
    try:
        text = json.dumps(value, indent=2, sort_keys=True, default=str)
    except TypeError:
        text = str(value)

    max_chars = int(os.environ.get("MCP_LOG_MAX_CHARS", "20000"))
    if len(text) <= max_chars:
        return text
    return f"{text[:max_chars]}\n... truncated {len(text) - max_chars} chars"


def _working_dir(cwd: str) -> Path:
    path = Path(cwd).expanduser()
    if not path.is_absolute():
        path = Path(DEFAULT_CWD) / path
    return path


@mcp.tool()
def bash(command: str, cwd: str = DEFAULT_CWD, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS) -> str:
    """Run a Bash command inside the HexStrike container."""

    arguments = {"command": command, "cwd": cwd, "timeout_seconds": timeout_seconds}
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug("MCP tool input name=bash arguments=%s", _log_payload(arguments))

    if not command or not command.strip():
        return _log_bash_output("Refusing to run an empty command.")

    timeout = max(1, min(int(timeout_seconds), MAX_TIMEOUT_SECONDS))
    working_dir = _working_dir(cwd)
    if not working_dir.exists() or not working_dir.is_dir():
        return _log_bash_output(f"Working directory does not exist or is not a directory: {cwd}")

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
        return _log_bash_output("\n\n".join(parts))

    stdout, stdout_truncated = _truncate(_text(completed.stdout), MAX_OUTPUT_BYTES)
    stderr, stderr_truncated = _truncate(_text(completed.stderr), MAX_OUTPUT_BYTES)
    parts = [
        f"exit_code: {completed.returncode}",
        f"cwd: {working_dir}",
        f"command: {command}",
        f"stdout{ ' (truncated)' if stdout_truncated else '' }:\n{stdout}",
        f"stderr{ ' (truncated)' if stderr_truncated else '' }:\n{stderr}",
    ]
    return _log_bash_output("\n\n".join(parts))


def _log_bash_output(output: str) -> str:
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug("MCP tool output name=bash output=%s", _log_payload(output))
    return output


def main() -> None:
    transport = os.environ.get("HEXSTRIKE_BASH_MCP_TRANSPORT", "streamable-http").lower()
    log_level = _log_level()
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        stream=sys.stdout,
        force=True,
    )
    logging.getLogger().setLevel(log_level)
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    logging.getLogger("mcp").setLevel(logging.INFO)
    logger.info(
        "Starting HexStrike Bash MCP server (transport=%s, host=%s, port=%d)",
        transport,
        MCP_HOST,
        MCP_PORT,
    )
    mcp.run(transport=transport)


if __name__ == "__main__":
    main()
