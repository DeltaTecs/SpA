"""Tolerant JSON extraction shared by analysis tasks.

Models often wrap their JSON in prose or code fences. These helpers strip a
leading/trailing fence and fall back to the first balanced array/object
substring, so a task parser can recover structured output from imperfect text.
"""

from __future__ import annotations

import json
from typing import Any, Optional


def strip_code_fence(text: str) -> str:
    """Drop a leading ```/```json fence and a trailing closing fence, if present."""
    if not text.startswith("```"):
        return text
    lines = text.splitlines()
    lines = lines[1:]
    if lines and lines[-1].strip().startswith("```"):
        lines = lines[:-1]
    return "\n".join(lines).strip()


def load_json(raw: str) -> Optional[Any]:
    """Best-effort parse of JSON embedded in model text.

    Tries a direct parse first, then the first balanced ``[...]`` or ``{...}``
    substring. Returns ``None`` when nothing parseable is found.
    """
    text = strip_code_fence(raw.strip())
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    for open_ch, close_ch in (("[", "]"), ("{", "}")):
        start = text.find(open_ch)
        end = text.rfind(close_ch)
        if start != -1 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                continue
    return None


def preview(text: str, max_chars: int = 2000) -> str:
    """Truncate long text for safe inclusion in a result payload."""
    if len(text) <= max_chars:
        return text
    return f"{text[:max_chars]}... (truncated)"
