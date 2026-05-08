from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple


logger = logging.getLogger(__name__)


@dataclass
class UserAction:
    """A single user action parsed from the intend file."""

    offset_ms: int
    description: str


def parse_intend_file(path: str) -> List[UserAction]:
    """Parse MM:SS action lines into recording-relative user actions."""

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
            minutes, seconds = int(match.group(1)), int(match.group(2))
            offset_ms = (minutes * 60 + seconds) * 1000
            actions.append(UserAction(offset_ms=offset_ms, description=match.group(3)))

    actions.sort(key=lambda action: action.offset_ms)
    logger.info("Parsed %d user actions from %s", len(actions), path)
    return actions


def load_app_details(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        text = fh.read().strip()
    logger.info("Loaded app details from %s (%d chars)", path, len(text))
    return text


def recent_user_actions(
    actions: List[UserAction],
    packet_offset_ms: int,
    n: int = 5,
) -> List[Tuple[UserAction, int]]:
    preceding = [
        (action, packet_offset_ms - action.offset_ms)
        for action in actions
        if action.offset_ms <= packet_offset_ms
    ]
    preceding.sort(key=lambda item: item[1])
    return preceding[:n]


def format_user_context(
    app_details: Optional[str],
    actions: Optional[List[UserAction]],
    packet_offset_ms: Optional[int],
) -> str:
    parts: List[str] = []

    if app_details:
        parts.append(
            "=== Application Details ===\n"
            f"{app_details}\n"
            "=== End Application Details ==="
        )

    if actions and packet_offset_ms is not None:
        recent = recent_user_actions(actions, packet_offset_ms)
        if recent:
            lines = ["=== Recent User Actions (most recent first) ==="]
            for action, delta_ms in recent:
                lines.append(f"  [{delta_ms:+d} ms]  {action.description}")
            lines.append("=== End User Actions ===")
            parts.append("\n".join(lines))

    return "\n\n".join(parts)
