"""Map the in-memory :class:`GuidedTurn` to the wire :class:`GuidedTurnStatus`."""

from __future__ import annotations

from ..schemas import GuidedTurnStatus
from .store import GuidedTurn


def build_guided_status(turn: GuidedTurn) -> GuidedTurnStatus:
    """Serialize a guided turn snapshot into its public ``GuidedTurnStatus``."""
    return GuidedTurnStatus(
        job_id=turn.job_id,
        status=turn.status,
        content=turn.content,
        error=turn.error,
        iterations=turn.iterations,
        stopped_on_limit=turn.stopped_on_limit,
        activity=turn.activity,
        pending_reviews=[
            {
                "review_id": review.review_id,
                "item_id": review.item_id,
                "tool_name": review.tool_name,
                "arguments": review.arguments,
                "auto_reason": review.auto_reason,
                "created_at": review.created_at,
            }
            for review in turn.pending_reviews
        ],
    )
