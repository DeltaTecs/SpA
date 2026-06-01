"""Thread-safe, in-memory store of guided-analysis chat turns and tool reviews.

A *turn* is one agentic chat exchange: the user sends a message and the model
runs the agentic loop (optionally calling tools) to produce a reply. Like a
single-item :class:`~app.pentest.store.PentestJob`, a turn can park a tool call
here awaiting a human decision while its worker thread blocks; the blocking
``threading.Event`` and the decision live in side tables (keyed by review id) so
``get`` can deep-copy the turn without touching live primitives.

Turns do not survive a process restart (acceptable for the PoC).
"""

from __future__ import annotations

import copy
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

from llm import CallBudget, CancellationToken


@dataclass
class ReviewRecord:
    """Serializable view of a tool call awaiting a decision."""

    review_id: str
    item_id: str
    tool_name: str
    arguments: Dict[str, Any]
    auto_reason: Optional[str]
    created_at: float


@dataclass
class GuidedTurn:
    """One agentic chat turn and its terminal result."""

    job_id: str
    provider: str
    model: Optional[str]
    reasoning_effort: Optional[str]
    status: str = "running"  # running | done | error | cancelled
    content: Optional[str] = None
    error: Optional[str] = None
    iterations: Optional[int] = None
    stopped_on_limit: Optional[bool] = None
    #: Current phase of the running turn ("thinking", "running tool X", ...).
    activity: Optional[str] = None
    pending_reviews: List[ReviewRecord] = field(default_factory=list)


class GuidedStore:
    """Holds guided chat turns in memory, guarded by a single lock.

    Mirrors the tool-review and cancellation mechanics of
    :class:`~app.pentest.store.PentestStore` so the shared
    :class:`~app.pentest.approver.PentestApprover` gate works against it
    unchanged, but models a single turn rather than a multi-item job.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._turns: Dict[str, GuidedTurn] = {}
        # Side tables for blocking reviews, keyed by review_id. Kept separate from
        # the turn objects so ``get`` can deep-copy without touching live Events.
        self._events: Dict[str, threading.Event] = {}
        self._decisions: Dict[str, Tuple[bool, str]] = {}
        # Per-turn cancellation token (shared with the turn's session). Kept out of
        # the turn objects so ``get`` can deep-copy freely.
        self._tokens: Dict[str, CancellationToken] = {}
        # Per-turn tool-call budget (a guided turn is its own job).
        self._budgets: Dict[str, CallBudget] = {}

    def create(
        self,
        *,
        provider: str,
        model: Optional[str],
        reasoning_effort: Optional[str],
        call_budget: int = 0,
    ) -> str:
        """Create a turn and return its id."""
        job_id = uuid4().hex
        turn = GuidedTurn(
            job_id=job_id,
            provider=provider,
            model=model,
            reasoning_effort=reasoning_effort,
        )
        with self._lock:
            self._turns[job_id] = turn
            self._tokens[job_id] = CancellationToken()
            # Per-turn budget for the turn's session (<= 0 = unlimited).
            self._budgets[job_id] = CallBudget(call_budget)
        return job_id

    def get(self, job_id: str) -> Optional[GuidedTurn]:
        """Return a deep copy of the turn so callers never see live mutations."""
        with self._lock:
            turn = self._turns.get(job_id)
            return copy.deepcopy(turn) if turn is not None else None

    def token_for(self, job_id: str) -> Optional[CancellationToken]:
        """Return the turn's cancellation token (shared with its session)."""
        with self._lock:
            return self._tokens.get(job_id)

    def budget_for(self, job_id: str) -> Optional[CallBudget]:
        """Return the turn's tool-call budget (or ``None`` if unknown)."""
        with self._lock:
            return self._budgets.get(job_id)

    def update(self, job_id: str, **fields: Any) -> None:
        """Patch turn fields, unless the turn was frozen by cancellation."""
        with self._lock:
            token = self._tokens.get(job_id)
            if token is not None and token.is_cancelled:
                return  # frozen after termination; keep the cancelled snapshot
            turn = self._turns.get(job_id)
            if turn is None:
                return
            for key, value in fields.items():
                setattr(turn, key, value)

    def cancel(self, job_id: str) -> bool:
        """Terminate a turn: set its token, mark it cancelled, and release a
        session blocked on a manual tool review.

        Returns ``False`` if the turn is unknown.
        """
        with self._lock:
            turn = self._turns.get(job_id)
            token = self._tokens.get(job_id)
            if turn is None or token is None:
                return False
            token.cancel()
            if turn.status in ("running",):
                turn.status = "cancelled"
                turn.activity = None
            # Deny and wake every parked review so the worker thread unblocks; the
            # run loop then observes the token and stops.
            for review in turn.pending_reviews:
                self._decisions[review.review_id] = (False, "Terminated by operator.")
                event = self._events.get(review.review_id)
                if event is not None:
                    event.set()
            turn.pending_reviews = []
        return True

    # -- tool reviews -------------------------------------------------------

    def open_review(
        self,
        job_id: str,
        item_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        auto_reason: Optional[str] = None,
    ) -> Tuple[str, threading.Event]:
        """Register a pending review and return its id plus a wait Event.

        The caller waits on the Event *without* holding the store lock; the API
        side resolves it via :meth:`resolve_review`. The ``item_id`` argument keeps
        the same shape the shared approver passes; for a guided turn it is a fixed
        sentinel (one session per turn).
        """
        review_id = uuid4().hex
        event = threading.Event()
        record = ReviewRecord(
            review_id=review_id,
            item_id=item_id,
            tool_name=tool_name,
            arguments=arguments,
            auto_reason=auto_reason,
            created_at=time.time(),
        )
        with self._lock:
            self._events[review_id] = event
            turn = self._turns.get(job_id)
            if turn is not None:
                turn.pending_reviews.append(record)
        return review_id, event

    def resolve_review(self, job_id: str, review_id: str, approved: bool, hint: str) -> bool:
        """Record a decision and wake the blocked worker. False if unknown."""
        with self._lock:
            event = self._events.get(review_id)
            if event is None:
                return False
            self._decisions[review_id] = (approved, hint)
            turn = self._turns.get(job_id)
            if turn is not None:
                turn.pending_reviews = [
                    r for r in turn.pending_reviews if r.review_id != review_id
                ]
            event.set()
            return True

    def take_decision(self, review_id: str) -> Tuple[bool, str]:
        """Consume and return the decision for a resolved review.

        Defaults to deny if no decision was recorded (defensive; should not
        happen because the worker only calls this after the Event is set).
        """
        with self._lock:
            self._events.pop(review_id, None)
            return self._decisions.pop(review_id, (False, "review was not resolved"))
