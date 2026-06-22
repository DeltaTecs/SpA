"""Logging configuration for the scanner frontend server.

Writes a rotating file under ``poc/logs`` (overridable via ``FRONTEND_LOG_DIR``)
plus console output, following the project-wide format and ``LOG_LEVEL``
convention (``VERBOSE`` -> DEBUG).
"""

from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

LOG_FILE_NAME = "scanner-frontend.log"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

_configured = False


def log_level() -> int:
    normalized = os.environ.get("LOG_LEVEL", "INFO").strip().upper()
    if normalized == "VERBOSE":
        return logging.DEBUG
    return getattr(logging, normalized, logging.INFO)


def log_dir() -> Path:
    """Return the log directory.

    Defaults to ``poc/logs`` (four parents up: ``app`` -> ``server`` ->
    ``frontend`` -> ``scanner`` -> ``poc``). Overridable via ``FRONTEND_LOG_DIR``.
    """

    override = os.environ.get("FRONTEND_LOG_DIR")
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[4] / "logs"


def configure_logging(*, force: bool = False) -> Path:
    """Configure file + console logging. Idempotent. Returns the log file path."""

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

    file_handler = RotatingFileHandler(
        log_file, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(level)

    for handler in list(root.handlers):
        root.removeHandler(handler)
    root.addHandler(file_handler)
    root.addHandler(console_handler)

    # The proxy already logs each request; silence uvicorn's duplicate access log
    # and the chatty http client internals even when running at DEBUG.
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)

    _configured = True
    logging.getLogger(__name__).info(
        "Logging configured -> %s (level=%s)", log_file, logging.getLevelName(level)
    )
    return log_file
