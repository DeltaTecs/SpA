"""Serialize an agentic run's transcript into a stable, classified, JSON-ready form.

:class:`~llm.TranscriptStep` is provider- and app-neutral — it records the owning
*toolset name* but knows nothing about pentest tool *categories*. This module is the
single place that turns a run's transcript into the dicts the stores keep, the
db-api persists, and the frontend renders, attaching the coarse ``category`` of each
tool call (so the Tool Transcript page can filter out DB-access and web-search steps).

Keeping the shape in one function guarantees the live (in-memory) and persisted
(db-api) transcripts a user opens are byte-identical.
"""

from __future__ import annotations

from typing import Any, Dict, List

from llm import TranscriptStep

from .mcp_catalog import category_for_toolset


def serialize_step(step: TranscriptStep) -> Dict[str, Any]:
    """Convert one :class:`TranscriptStep` into its JSON-ready dict."""
    if step.kind == "reasoning":
        return {"kind": "reasoning", "text": step.text, "reasoning": step.reasoning}
    return {
        "kind": "tool_call",
        "call_id": step.call_id,
        "tool_name": step.tool_name,
        "toolset_name": step.toolset_name,
        "category": category_for_toolset(step.toolset_name),
        "arguments": step.arguments,
        "output": step.output,
        "approved": step.approved,
        "review_feedback": step.review_feedback,
    }


def serialize_transcript(steps: List[TranscriptStep]) -> List[Dict[str, Any]]:
    """Convert a run's transcript into the list of dicts stored and served."""
    return [serialize_step(step) for step in steps]
