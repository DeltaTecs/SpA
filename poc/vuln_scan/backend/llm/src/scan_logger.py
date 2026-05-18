"""Per-run, on-disk log capture for vulnerability scans.

Each scan run (phase 1 or phase 2) gets its own folder named
``<phase>_<timestamp>[_<event_id>][_<run_id>]`` under ``SCAN_LOG_ROOT``.

Within that folder three files capture different verbosity tiers:

* ``run.info``  - high-level milestones (started, completed, user actions, errors)
* ``run.debug`` - INFO + DEBUG (intermediate state, control-flow detail)
* ``run.trace`` - everything: prompts, LLM responses, MCP tool calls/results

Each file is a threshold tier; ``run.trace`` is the most complete superset.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from datetime import datetime
from typing import Any, Optional


TRACE_LEVEL = 5
logging.addLevelName(TRACE_LEVEL, "TRACE")


_DEFAULT_ROOT = "/logs/vuln_scan"
_LOGGER_PREFIX = "vuln_scan.run"
_PAYLOAD_FORMAT = "%(asctime)s | %(levelname)-5s | %(message)s"


def _scan_log_root() -> str:
    root = os.environ.get("SCAN_LOG_ROOT", "").strip()
    return root or _DEFAULT_ROOT


def _safe_segment(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    safe = re.sub(r"_+", "_", safe).strip("_")
    return safe or "x"


def _format_payload(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, indent=2, sort_keys=True, default=str, ensure_ascii=False)
    except TypeError:
        return str(value)


class ScanRunLogger:
    """Capture a single scan run's inputs, outputs, tool I/O and user actions."""

    def __init__(
        self,
        *,
        phase: str,
        run_id: str,
        event_id: Optional[int],
        folder: str,
        logger: logging.Logger,
        handlers: list[logging.Handler],
    ) -> None:
        self.phase = phase
        self.run_id = run_id
        self.event_id = event_id
        self.folder = folder
        self._logger = logger
        self._handlers = handlers
        self._closed = False
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # raw level emitters

    def info(self, message: str, *args: Any) -> None:
        self._emit(logging.INFO, message, args)

    def debug(self, message: str, *args: Any) -> None:
        self._emit(logging.DEBUG, message, args)

    def trace(self, message: str, *args: Any) -> None:
        self._emit(TRACE_LEVEL, message, args)

    def warning(self, message: str, *args: Any) -> None:
        self._emit(logging.WARNING, message, args)

    def error(self, message: str, *args: Any) -> None:
        self._emit(logging.ERROR, message, args)

    def _emit(self, level: int, message: str, args: tuple) -> None:
        if self._closed:
            return
        try:
            self._logger.log(level, message, *args)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # semantic helpers

    def section(self, title: str) -> None:
        bar = "=" * max(8, 60 - len(title))
        self.info("=== %s %s", title, bar)

    def log_input(self, name: str, value: Any) -> None:
        self.trace("INPUT %s:\n%s", name, _format_payload(value))

    def log_output(self, name: str, value: Any) -> None:
        self.trace("OUTPUT %s:\n%s", name, _format_payload(value))

    def log_progress(self, message: str) -> None:
        self.info("PROGRESS %s", message)

    def log_user_action(self, action: str, detail: Any = None) -> None:
        if detail is None:
            self.info("USER %s", action)
        else:
            self.info("USER %s:\n%s", action, _format_payload(detail))

    def log_tool_request(self, tool_name: str, arguments: Any, source: str = "llm") -> None:
        self.trace(
            "TOOL_REQUEST source=%s tool=%s arguments=%s",
            source,
            tool_name,
            _format_payload(arguments),
        )

    def log_tool_response(self, tool_name: str, result: Any) -> None:
        self.trace(
            "TOOL_RESPONSE tool=%s result=%s",
            tool_name,
            _format_payload(result),
        )

    def log_llm_request(self, label: str, payload: Any) -> None:
        self.trace("LLM_REQUEST %s:\n%s", label, _format_payload(payload))

    def log_llm_response(self, label: str, payload: Any) -> None:
        self.trace("LLM_RESPONSE %s:\n%s", label, _format_payload(payload))

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            for handler in list(self._handlers):
                try:
                    self._logger.removeHandler(handler)
                except Exception:
                    pass
                try:
                    handler.flush()
                    handler.close()
                except Exception:
                    pass


class _ThresholdFilter(logging.Filter):
    """Pass records whose level is >= ``threshold``."""

    def __init__(self, threshold: int) -> None:
        super().__init__()
        self._threshold = threshold

    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno >= self._threshold


def create_scan_run_logger(
    *,
    phase: str,
    run_id: str,
    event_id: Optional[int] = None,
    root_dir: Optional[str] = None,
) -> Optional[ScanRunLogger]:
    """Create a per-run logger backed by INFO/DEBUG/TRACE files.

    Returns ``None`` only if the log directory cannot be created (the runners
    treat that as a soft failure and continue without per-run files).
    """

    root = root_dir or _scan_log_root()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    parts: list[str] = [_safe_segment(phase), timestamp]
    if event_id is not None:
        parts.append(f"event{event_id}")
    if run_id:
        parts.append(_safe_segment(run_id)[:12])
    folder = os.path.join(root, "_".join(parts))

    try:
        os.makedirs(folder, exist_ok=True)
    except Exception as exc:  # pragma: no cover - depends on host fs
        logging.getLogger(__name__).warning(
            "Failed to create scan log folder %s: %s", folder, exc
        )
        return None

    logger_name = f"{_LOGGER_PREFIX}.{_safe_segment(phase)}.{run_id or timestamp}"
    logger = logging.getLogger(logger_name)
    logger.setLevel(TRACE_LEVEL)
    logger.propagate = False

    formatter = logging.Formatter(_PAYLOAD_FORMAT)
    handlers: list[logging.Handler] = []
    for filename, threshold in (
        ("run.info", logging.INFO),
        ("run.debug", logging.DEBUG),
        ("run.trace", TRACE_LEVEL),
    ):
        path = os.path.join(folder, filename)
        handler = logging.FileHandler(path, encoding="utf-8")
        handler.setLevel(threshold)
        handler.addFilter(_ThresholdFilter(threshold))
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        handlers.append(handler)

    run_logger = ScanRunLogger(
        phase=phase,
        run_id=run_id,
        event_id=event_id,
        folder=folder,
        logger=logger,
        handlers=handlers,
    )
    run_logger.info(
        "Scan run logger initialised phase=%s run_id=%s event_id=%s folder=%s started_at=%s",
        phase,
        run_id,
        event_id,
        folder,
        datetime.utcnow().isoformat() + "Z",
    )
    return run_logger
