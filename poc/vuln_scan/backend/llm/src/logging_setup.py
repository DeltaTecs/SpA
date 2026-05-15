from __future__ import annotations

import logging
import os
import sys


def _log_level(value: int | str | None) -> int:
    if isinstance(value, int):
        return value
    normalized = (value or os.environ.get("LOG_LEVEL") or "INFO").strip().upper()
    if normalized == "VERBOSE":
        return logging.DEBUG
    return getattr(logging, normalized, logging.INFO)


def configure_logging(level: int | str | None = None) -> None:
    resolved_level = _log_level(level)
    logging.basicConfig(
        level=resolved_level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        stream=sys.stdout,
        force=True,
    )
    logging.getLogger().setLevel(resolved_level)

    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)
    logging.getLogger("requests.packages.urllib3").setLevel(logging.WARNING)
    logging.getLogger("openai._base_client").setLevel(logging.WARNING)
