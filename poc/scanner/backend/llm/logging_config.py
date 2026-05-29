"""Logging configuration for the LLM / MCP client module.

Logs are written to a rotating file under ``poc/logs`` (overridable via the
``LLM_LOG_DIR`` environment variable) and, additionally, to the console. The
level honours the project-wide ``LOG_LEVEL`` convention where ``VERBOSE`` maps
to ``DEBUG``.
"""

from __future__ import annotations

import json
import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

#: Default log file name written into the resolved log directory.
LOG_FILE_NAME = "scanner-llm.log"

#: Shared format, matching the rest of the ``poc`` services but with the logger
#: name included so the originating module is visible across the LLM package.
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

_configured = False


def log_level() -> int:
    """Resolve the effective log level from ``LOG_LEVEL`` (``VERBOSE`` -> DEBUG)."""

    normalized = os.environ.get("LOG_LEVEL", "INFO").strip().upper()
    if normalized == "VERBOSE":
        return logging.DEBUG
    return getattr(logging, normalized, logging.INFO)


def log_dir() -> Path:
    """Return the directory log files are written to.

    Defaults to ``poc/logs`` (three parents up from this file:
    ``llm`` -> ``backend`` -> ``scanner`` -> ``poc``). Overridable via
    ``LLM_LOG_DIR`` so the location can be redirected in containers/tests.
    """

    override = os.environ.get("LLM_LOG_DIR")
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[3] / "logs"


def configure_logging(*, force: bool = False) -> Path:
    """Configure file + console logging for the package. Idempotent.

    Attaches a :class:`~logging.handlers.RotatingFileHandler` writing to
    ``<log_dir>/scanner-llm.log`` plus a console handler. Calling this more than
    once is a no-op unless ``force`` is set, so importing several modules from
    this package never duplicates handlers.

    Returns the path to the log file.
    """

    global _configured

    directory = log_dir()
    log_file = directory / LOG_FILE_NAME

    if _configured and not force:
        return log_file

    directory.mkdir(parents=True, exist_ok=True)

    level = log_level()
    root = logging.getLogger()
    root.setLevel(level)

    formatter = logging.Formatter(LOG_FORMAT)

    # 5 MB per file, keep 3 backups; keeps logs bounded during long agent runs.
    file_handler = RotatingFileHandler(
        log_file, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(level)

    # Replace any previously installed handlers to avoid duplicate lines.
    for handler in list(root.handlers):
        root.removeHandler(handler)
    root.addHandler(file_handler)
    root.addHandler(console_handler)

    # Keep noisy third-party loggers from drowning the file at DEBUG.
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.INFO)
    logging.getLogger("mcp").setLevel(logging.INFO)

    _configured = True
    logging.getLogger(__name__).info("Logging configured -> %s (level=%s)", log_file, logging.getLevelName(level))
    return log_file


def log_payload(value: Any, *, max_chars: int | None = None) -> str:
    """Render ``value`` as pretty JSON, truncated for safe DEBUG logging.

    Mirrors the ``_log_payload`` helper used across the MCP services so tool
    inputs/outputs are logged consistently and never flood the log file.
    """

    try:
        text = json.dumps(value, indent=2, sort_keys=True, default=str)
    except TypeError:
        text = str(value)

    limit = max_chars if max_chars is not None else int(os.environ.get("LLM_LOG_MAX_CHARS", "20000"))
    if len(text) <= limit:
        return text
    return f"{text[:limit]}\n... truncated {len(text) - limit} chars"
