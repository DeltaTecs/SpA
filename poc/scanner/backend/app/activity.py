"""Per-session activity reporting.

Bridges the generic orchestrator's activity hook (:class:`llm.ActivityReporter`)
and the pentest approval gate to a job store, so the UI can show what each
running LLM session is currently doing ("thinking", "running tool X", "waiting
for approval", "auto approver reviewing").

Keeping the store coupling here means the ``llm`` orchestrator and the approver
stay store-agnostic: the owning runner supplies a thin ``write`` setter (e.g. a
closure over ``store.update_item(job_id, item_id, activity=...)``) and this class
turns each phase into the human-readable phrase the frontend renders verbatim.
"""

from __future__ import annotations

from typing import Callable, Optional

#: Human-readable activity phrases. Surfaced to the UI as-is (see the frontend
#: ``JobProgress`` label), so changing one is a user-visible change.
THINKING = "thinking"
WAITING_FOR_APPROVAL = "waiting for approval"
AUTO_REVIEW = "auto approver reviewing"


def running_tool(tool_name: str) -> str:
    """Phrase for the model executing a named tool."""
    return f"running tool {tool_name}"


class SessionActivity:
    """Funnels one session's phase changes to its job-store entry.

    Implements the structural :class:`llm.ActivityReporter` surface the
    orchestrator expects (``on_thinking`` / ``on_tool_call``) and adds the two
    approval phases reported by :class:`~app.pentest.approver.PentestApprover`.
    """

    def __init__(self, write: Callable[[Optional[str]], None]) -> None:
        self._write = write

    # -- llm.ActivityReporter ----------------------------------------------
    def on_thinking(self) -> None:
        self._write(THINKING)

    def on_tool_call(self, tool_name: str) -> None:
        self._write(running_tool(tool_name))

    # -- approval phases (pentest only) ------------------------------------
    def on_waiting_for_approval(self) -> None:
        self._write(WAITING_FOR_APPROVAL)

    def on_auto_review(self) -> None:
        self._write(AUTO_REVIEW)
