from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import List, Optional


logger = logging.getLogger(__name__)


@dataclass
class UserAction:
    offset_ms: int
    description: str


def parse_intend_file(path: str) -> List[UserAction]:
    actions: List[UserAction] = []
    with open(path, encoding="utf-8") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line:
                continue
            match = re.match(r"^(\d+):(\d{2})\s+(.+)$", line)
            if not match:
                logger.debug("Skipping unparseable intend line: %s", line)
                continue
            minutes = int(match.group(1))
            seconds = int(match.group(2))
            actions.append(
                UserAction(
                    offset_ms=(minutes * 60 + seconds) * 1000,
                    description=match.group(3),
                )
            )

    actions.sort(key=lambda action: action.offset_ms)
    logger.info("Parsed %d user actions from %s", len(actions), path)
    return actions


def load_app_details(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        text = fh.read().strip()
    logger.info("Loaded app details from %s (%d chars)", path, len(text))
    return text


def format_user_context(
    app_details: Optional[str],
    actions: Optional[List[UserAction]],
    event_start_offset_ms: Optional[int],
    event_end_offset_ms: Optional[int],
) -> str:
    parts: List[str] = []

    if app_details:
        parts.append(
            "=== Application Details ===\n"
            f"{app_details}\n"
            "=== End Application Details ==="
        )

    if actions and event_start_offset_ms is not None and event_end_offset_ms is not None:
        start = min(event_start_offset_ms, event_end_offset_ms)
        end = max(event_start_offset_ms, event_end_offset_ms)
        window_start = max(0, start - 5_000)
        window_end = end + 5_000
        nearby = [
            action for action in actions if window_start <= action.offset_ms <= window_end
        ]
        if not nearby:
            preceding = [action for action in actions if action.offset_ms <= start]
            nearby = preceding[-3:]

        if nearby:
            lines = ["=== User Actions Near Event ==="]
            for action in nearby:
                delta = action.offset_ms - start
                lines.append(
                    f"  [{action.offset_ms} ms, {delta:+d} ms from event start] "
                    f"{action.description}"
                )
            lines.append("=== End User Actions ===")
            parts.append("\n".join(lines))

    return "\n\n".join(parts)
