#!/opt/hexstrike-venv/bin/python
from __future__ import annotations

import json
import logging
import os
import signal
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path

try:
    from mcp.server.fastmcp import FastMCP
    from mcp.server.fastmcp.server import TransportSecuritySettings
except ImportError as e:  # pragma: no cover
    raise RuntimeError("mcp package is required") from e

from cli_tools_catalog import (
    find_cli_tool,
    format_cli_tool_list,
    format_tool_example,
    format_tool_help,
    is_installed,
)


MCP_HOST = os.environ.get("HEXSTRIKE_BASH_MCP_HOST", "0.0.0.0")
MCP_PORT = int(os.environ.get("HEXSTRIKE_BASH_MCP_PORT", "8766"))
DEFAULT_CWD = os.environ.get("HEXSTRIKE_BASH_MCP_CWD", "/workspace")
DEFAULT_TIMEOUT_SECONDS = int(os.environ.get("HEXSTRIKE_BASH_MCP_TIMEOUT", "60"))
MAX_TIMEOUT_SECONDS = int(os.environ.get("HEXSTRIKE_BASH_MCP_MAX_TIMEOUT", "300"))
MAX_OUTPUT_BYTES = int(os.environ.get("HEXSTRIKE_BASH_MCP_MAX_OUTPUT_BYTES", "65536"))
# How long a `cli_tool_usage(detailed=True)` --help invocation may run.
HELP_TIMEOUT_SECONDS = int(os.environ.get("HEXSTRIKE_BASH_MCP_HELP_TIMEOUT", "30"))
logger = logging.getLogger(__name__)
_active_processes_lock = threading.RLock()
_active_processes: dict[int, "ActiveBashProcess"] = {}


@dataclass
class ActiveBashProcess:
    process: subprocess.Popen[str]
    command: str
    cwd: Path
    stop_requested: bool = False


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

    record: ActiveBashProcess | None = None
    try:
        process = subprocess.Popen(
            ["/bin/bash", "-lc", command],
            cwd=str(working_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        record = ActiveBashProcess(process=process, command=command, cwd=working_dir)
        with _active_processes_lock:
            _active_processes[process.pid] = record

        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as e:
        if record is not None:
            _terminate_process_group(record.process)
            stdout, stderr = record.process.communicate()
        else:
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
    finally:
        if record is not None:
            with _active_processes_lock:
                _active_processes.pop(record.process.pid, None)

    stdout, stdout_truncated = _truncate(_text(stdout), MAX_OUTPUT_BYTES)
    stderr, stderr_truncated = _truncate(_text(stderr), MAX_OUTPUT_BYTES)
    status = (
        "Stopped by user."
        if record is not None and record.stop_requested
        else f"exit_code: {process.returncode}"
    )
    parts = [
        status,
        f"cwd: {working_dir}",
        f"command: {command}",
        f"stdout{ ' (truncated)' if stdout_truncated else '' }:\n{stdout}",
        f"stderr{ ' (truncated)' if stderr_truncated else '' }:\n{stderr}",
    ]
    return _log_bash_output("\n\n".join(parts))


@mcp.tool()
def stop_active_bash() -> str:
    """Stop any currently running Bash command started by this MCP server."""

    with _active_processes_lock:
        active = list(_active_processes.values())
        for record in active:
            record.stop_requested = True

    if not active:
        return "No active Bash process."

    for record in active:
        _terminate_process_group(record.process)

    return f"Stop requested for {len(active)} active Bash process(es)."


@mcp.tool()
def list_cli_tools() -> str:
    """List the CLI security tools installed in the HexStrike container.

    These are the binaries HexStrike would otherwise invoke itself. Run them
    yourself with the `bash` tool, and call `cli_tool_usage` to learn how.
    """

    if logger.isEnabledFor(logging.DEBUG):
        logger.debug("MCP tool input name=list_cli_tools arguments={}")

    output = format_cli_tool_list()
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug("MCP tool output name=list_cli_tools output=%s", _log_payload(output))
    return output


@mcp.tool()
def cli_tool_usage(binary_name: str, detailed: bool = False) -> str:
    """Explain how to use one CLI security tool from `list_cli_tools`.

    With ``detailed=False`` (the default) a short, low-impact example invocation
    is returned. With ``detailed=True`` the tool's own ``--help`` output is
    returned instead. Examples set a custom HTTP User-Agent and a request rate
    limit wherever the tool supports them.
    """

    arguments = {"binary_name": binary_name, "detailed": detailed}
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(
            "MCP tool input name=cli_tool_usage arguments=%s", _log_payload(arguments)
        )

    tool = find_cli_tool(binary_name)
    if tool is None:
        output = (
            f"Unknown CLI tool: {binary_name!r}. "
            "Call list_cli_tools for the catalogue of available tools."
        )
    else:
        installed = is_installed(tool.binary)
        if not detailed:
            output = format_tool_example(tool, installed=installed)
        elif not installed:
            output = (
                format_tool_example(tool, installed=installed)
                + "\n\nDetailed --help is unavailable because the binary is not "
                "installed in this container."
            )
        else:
            help_command, help_text = _capture_tool_help(tool)
            output = format_tool_help(
                tool, help_command=help_command, help_text=help_text
            )

    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(
            "MCP tool output name=cli_tool_usage output=%s", _log_payload(output)
        )
    return output


def _capture_tool_help(tool) -> tuple[str, str]:
    """Run a catalogued tool's help command and return ``(command, output)``."""

    argv = [tool.binary, *tool.help_arg.split()]
    command = " ".join(argv).strip()
    cwd = DEFAULT_CWD if os.path.isdir(DEFAULT_CWD) else None

    try:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
    except OSError as exc:
        return command, f"Could not run `{command}`: {exc}"

    try:
        output, _ = process.communicate(timeout=HELP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        _terminate_process_group(process)
        output, _ = process.communicate()
        output = (
            f"{_text(output)}\n\n(`{command}` timed out after "
            f"{HELP_TIMEOUT_SECONDS} seconds)"
        )

    text, truncated = _truncate(_text(output), MAX_OUTPUT_BYTES)
    if truncated:
        text = f"{text}\n\n(help output truncated)"
    return command, text


def _terminate_process_group(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return

    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except OSError:
        process.terminate()

    try:
        process.wait(timeout=5)
        return
    except subprocess.TimeoutExpired:
        pass

    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    except OSError:
        process.kill()

    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        logger.warning("Bash process group %d did not exit after SIGKILL", process.pid)


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
