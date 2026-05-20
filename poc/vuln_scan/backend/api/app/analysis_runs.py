"""In-memory lifecycle of a phase-two vulnerability-analysis run.

An :class:`AnalysisRun` tracks one phase-two run: its progress log, the MCP
tool-approval workflow (:class:`ToolApprovalRequest`), the tool currently
executing (:class:`ActiveToolExecution`), and the final report. Active runs are
held in :class:`AnalysisSessionStore`. Nothing here is persisted; completed
reports are written to the database by ``scan_store``.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


logger = logging.getLogger(__name__)

TERMINAL_STATUSES = {"completed", "failed", "aborted"}

# How phase-two MCP tool calls are approved before the proxy runs them.
APPROVAL_MODE_MANUAL = "manual"
APPROVAL_MODE_AUTO_DB = "auto_db"
APPROVAL_MODE_AUTO_ALL = "auto_all"
APPROVAL_MODE_SMART_NON_DB = "smart_non_db"

APPROVAL_MODES = frozenset(
    {
        APPROVAL_MODE_MANUAL,
        APPROVAL_MODE_AUTO_DB,
        APPROVAL_MODE_AUTO_ALL,
        APPROVAL_MODE_SMART_NON_DB,
    }
)

# Callback used by the smart approval mode. Given a tool-call dict it returns a
# decision dict ``{"approved": bool, "reasoning": str, "error": bool}``.
SmartReviewCallback = Callable[[dict[str, Any]], dict[str, Any]]

_RUN_ABORTED_REASON = "The analysis run was aborted before the tool call could run."


@dataclass
class ToolApprovalRequest:
    request_id: str
    tool_call: dict[str, Any]
    status: str = "pending"
    created_at: float = field(default_factory=time.time)
    decided_at: Optional[float] = None
    # Decision from the LLM smart approver, when the smart mode reviewed this
    # call. Present on both auto-approved and escalated/denied requests.
    smart_review: Optional[dict[str, Any]] = None
    # Free-text reason captured when a user denies the call in manual review.
    decision_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "status": self.status,
            "created_at": self.created_at,
            "decided_at": self.decided_at,
            "tool_call": self.tool_call,
            "smart_review": self.smart_review,
            "decision_reason": self.decision_reason,
        }


@dataclass
class ActiveToolExecution:
    execution_id: str
    tool_call: dict[str, Any]
    status: str = "running"
    started_at: float = field(default_factory=time.time)
    stop_requested_at: Optional[float] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "status": self.status,
            "started_at": self.started_at,
            "stop_requested_at": self.stop_requested_at,
            "tool_call": self.tool_call,
        }


class AnalysisRun:
    def __init__(
        self,
        *,
        event_id: int,
        analysis_types: list[str],
        constraints: str,
        provider: str,
        model: str,
        approval_timeout_seconds: float,
        approval_mode: str = APPROVAL_MODE_MANUAL,
        approval_provider: Optional[str] = None,
        approval_model: Optional[str] = None,
        escalate_smart_rejections: bool = True,
    ):
        self.run_id = uuid.uuid4().hex
        self.event_id = event_id
        self.analysis_types = analysis_types
        self.constraints = constraints
        self.provider = provider
        self.model = model
        self.approval_timeout_seconds = approval_timeout_seconds
        self.approval_mode = (
            approval_mode if approval_mode in APPROVAL_MODES else APPROVAL_MODE_MANUAL
        )
        self.approval_provider = approval_provider
        self.approval_model = approval_model
        # When True, a tool call the smart approver rejects is escalated to the
        # user for a manual decision. When False, the rejection is final and is
        # returned straight to the analysis LLM.
        self.escalate_smart_rejections = escalate_smart_rejections
        self.status = "queued"
        self.progress: list[dict[str, Any]] = []
        self.tool_requests: dict[str, ToolApprovalRequest] = {}
        self.active_tool_execution: Optional[ActiveToolExecution] = None
        self.result_markdown = ""
        self.error: Optional[str] = None
        self.abort_requested = False
        self.created_at = time.time()
        self.updated_at = self.created_at
        self._smart_review_callback: Optional[SmartReviewCallback] = None
        self._condition = threading.Condition(threading.RLock())

    def attach_smart_reviewer(self, callback: Optional[SmartReviewCallback]) -> None:
        """Register the LLM smart approver used by the ``smart_non_db`` mode."""
        with self._condition:
            self._smart_review_callback = callback

    def add_progress(self, message: str) -> None:
        with self._condition:
            self.progress.append({"timestamp": time.time(), "message": message})
            self.updated_at = time.time()
            self._condition.notify_all()

    def start(self) -> None:
        with self._condition:
            self.status = "running"
            self.updated_at = time.time()
            self.progress.append({"timestamp": time.time(), "message": "Analysis started."})
            self._condition.notify_all()

    def complete(self, result_markdown: str) -> None:
        with self._condition:
            if self.abort_requested:
                self.status = "aborted"
                self.progress.append({"timestamp": time.time(), "message": "Analysis aborted."})
            else:
                self.status = "completed"
                self.result_markdown = result_markdown
                self.progress.append({"timestamp": time.time(), "message": "Analysis completed."})
            self.updated_at = time.time()
            self._condition.notify_all()

    def fail(self, error: str) -> None:
        with self._condition:
            self.status = "failed"
            self.error = error
            self.progress.append({"timestamp": time.time(), "message": f"Analysis failed: {error}"})
            self.updated_at = time.time()
            self._condition.notify_all()

    def abort(self) -> None:
        with self._condition:
            self.abort_requested = True
            if self.status not in TERMINAL_STATUSES:
                self.status = "aborted"
            for request in self.tool_requests.values():
                if request.status == "pending":
                    request.status = "aborted"
                    request.decided_at = time.time()
            if self.active_tool_execution and self.active_tool_execution.status == "running":
                self.active_tool_execution.status = "stop_requested"
                self.active_tool_execution.stop_requested_at = time.time()
            self.progress.append({"timestamp": time.time(), "message": "Abort requested."})
            self.updated_at = time.time()
            self._condition.notify_all()

    def request_tool_permission(self, tool_call: dict[str, Any]) -> tuple[bool, str]:
        """Approval callback for the MCP proxy.

        Resolves a single tool call through the configured approval mode and
        returns ``(approved, reason)``. ``reason`` is empty for approvals and,
        for denials, explains why so the analysis LLM can adjust the call.
        """
        request = self._register_tool_request(tool_call)
        if request is None:
            return False, _RUN_ABORTED_REASON

        static_reason = self._static_auto_approval_reason(tool_call)
        if static_reason is not None:
            self._record_auto_approval(request, static_reason)
            return True, ""

        if (
            self.approval_mode == APPROVAL_MODE_SMART_NON_DB
            and self._smart_review_callback is not None
        ):
            decision = self._run_smart_review(request, tool_call)
            if self.abort_requested:
                return False, _RUN_ABORTED_REASON
            if _is_approving_decision(decision):
                self._record_auto_approval(
                    request, "Smart approver approved", smart_review=decision
                )
                return True, ""

            rejection_reason = _smart_rejection_reason(decision)
            if not self.escalate_smart_rejections:
                # Manual fallback disabled: the rejection is final.
                self._record_auto_denial(request, decision)
                return False, rejection_reason

            self.add_progress(
                "Escalating rejected tool call to manual approval: "
                f"{_tool_display_name(tool_call)}."
            )

        return self._await_manual_decision(request)

    def _register_tool_request(
        self, tool_call: dict[str, Any]
    ) -> Optional[ToolApprovalRequest]:
        with self._condition:
            if self.abort_requested:
                return None
            request = ToolApprovalRequest(
                request_id=uuid.uuid4().hex, tool_call=tool_call
            )
            self.tool_requests[request.request_id] = request
            return request

    def _static_auto_approval_reason(self, tool_call: dict[str, Any]) -> Optional[str]:
        """Reason this call is approved without an LLM review, or ``None``."""
        if self.approval_mode == APPROVAL_MODE_AUTO_ALL:
            return "Auto-approve (all tools)"
        if _is_mcp_database_tool_call(tool_call) and self.approval_mode in (
            APPROVAL_MODE_AUTO_DB,
            APPROVAL_MODE_SMART_NON_DB,
        ):
            return "Auto-approve (database tool)"
        return None

    def _record_auto_approval(
        self,
        request: ToolApprovalRequest,
        reason: str,
        smart_review: Optional[dict[str, Any]] = None,
    ) -> None:
        with self._condition:
            request.status = "approved"
            request.decided_at = time.time()
            if smart_review is not None:
                request.smart_review = smart_review
            self.progress.append(
                {
                    "timestamp": time.time(),
                    "message": (
                        f"{reason}: {_tool_display_name(request.tool_call)} "
                        f"({request.request_id})"
                    ),
                }
            )
            self.updated_at = time.time()
            self._condition.notify_all()

    def _record_auto_denial(
        self,
        request: ToolApprovalRequest,
        smart_review: Optional[dict[str, Any]],
    ) -> None:
        """Finalize a smart-approver rejection when manual fallback is off."""
        with self._condition:
            request.status = "denied"
            request.decided_at = time.time()
            request.smart_review = smart_review
            self.progress.append(
                {
                    "timestamp": time.time(),
                    "message": (
                        "Manual fallback disabled; returned smart approver "
                        "rejection to the analysis LLM: "
                        f"{_tool_display_name(request.tool_call)} "
                        f"({request.request_id})"
                    ),
                }
            )
            self.updated_at = time.time()
            self._condition.notify_all()

    def _run_smart_review(
        self, request: ToolApprovalRequest, tool_call: dict[str, Any]
    ) -> Optional[dict[str, Any]]:
        """Run the LLM smart reviewer (outside the lock) and record its result."""
        tool_name = _tool_display_name(tool_call)
        self.add_progress(f"Smart approver is reviewing tool call: {tool_name}.")

        decision: Optional[dict[str, Any]] = None
        try:
            decision = self._smart_review_callback(tool_call)  # type: ignore[misc]
        except Exception as exc:  # noqa: BLE001 - reviewer must not crash the run
            logger.error("Smart approver callback failed: %s", exc)

        with self._condition:
            request.smart_review = decision
            if not _is_approving_decision(decision):
                self.progress.append(
                    {
                        "timestamp": time.time(),
                        "message": _smart_review_rejection_message(
                            tool_name, decision
                        ),
                    }
                )
                self.updated_at = time.time()
                self._condition.notify_all()
        return decision

    def _await_manual_decision(self, request: ToolApprovalRequest) -> tuple[bool, str]:
        """Block until the user approves/denies, the run aborts, or it times out."""
        with self._condition:
            if self.abort_requested:
                request.status = "aborted"
                request.decided_at = time.time()
                self._condition.notify_all()
                return False, _RUN_ABORTED_REASON

            self.status = "waiting_for_tool_approval"
            self.progress.append(
                {
                    "timestamp": time.time(),
                    "message": (
                        "Tool approval requested: "
                        f"{_tool_display_name(request.tool_call)}"
                    ),
                }
            )
            self.updated_at = time.time()
            self._condition.notify_all()

            deadline = time.monotonic() + self.approval_timeout_seconds
            while request.status == "pending" and not self.abort_requested:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    request.status = "timeout"
                    request.decided_at = time.time()
                    self.status = "running"
                    self.progress.append(
                        {
                            "timestamp": time.time(),
                            "message": f"Tool approval timed out: {request.request_id}",
                        }
                    )
                    self._condition.notify_all()
                    return False, (
                        "Tool approval timed out after "
                        f"{self.approval_timeout_seconds:.0f} seconds without a "
                        "decision."
                    )
                self._condition.wait(timeout=min(remaining, 5))

            if self.abort_requested:
                request.status = "aborted"
                request.decided_at = time.time()
                self._condition.notify_all()
                return False, _RUN_ABORTED_REASON

            self.status = "running"
            self.updated_at = time.time()
            self._condition.notify_all()
            if request.status == "approved":
                return True, ""
            return False, _manual_denial_reason(request)

    def start_tool_execution(self, tool_call: dict[str, Any]) -> str:
        with self._condition:
            execution_id = uuid.uuid4().hex
            self.active_tool_execution = ActiveToolExecution(
                execution_id=execution_id,
                tool_call=tool_call,
            )
            tool_name = _tool_display_name(tool_call)
            self.progress.append(
                {"timestamp": time.time(), "message": f"MCP tool running: {tool_name}"}
            )
            self.updated_at = time.time()
            self._condition.notify_all()
            return execution_id

    def request_active_tool_stop(self) -> bool:
        with self._condition:
            execution = self.active_tool_execution
            if execution is None or execution.status != "running":
                return False

            execution.status = "stop_requested"
            execution.stop_requested_at = time.time()
            tool_name = _tool_display_name(execution.tool_call)
            self.progress.append(
                {"timestamp": time.time(), "message": f"MCP tool stop requested: {tool_name}"}
            )
            self.updated_at = time.time()
            self._condition.notify_all()
            return True

    def is_tool_stop_requested(self, execution_id: str) -> bool:
        with self._condition:
            execution = self.active_tool_execution
            if self.abort_requested:
                return True
            return bool(
                execution
                and execution.execution_id == execution_id
                and execution.status == "stop_requested"
            )

    def finish_tool_execution(self, execution_id: str) -> None:
        with self._condition:
            execution = self.active_tool_execution
            if execution is None or execution.execution_id != execution_id:
                return

            tool_name = _tool_display_name(execution.tool_call)
            if execution.status == "stop_requested":
                self.progress.append(
                    {"timestamp": time.time(), "message": f"MCP tool stopped by user: {tool_name}"}
                )
            self.active_tool_execution = None
            self.updated_at = time.time()
            self._condition.notify_all()

    def tools_used(self) -> list[str]:
        with self._condition:
            return [
                _tool_display_name(request.tool_call)
                for request in sorted(
                    self.tool_requests.values(),
                    key=lambda item: item.created_at,
                )
                if request.status == "approved"
            ]

    def decide_tool_request(
        self, request_id: str, approved: bool, reason: str = ""
    ) -> None:
        with self._condition:
            request = self.tool_requests.get(request_id)
            if request is None:
                raise KeyError(request_id)
            if request.status != "pending":
                raise ValueError(f"Tool request {request_id} is already {request.status}")
            request.status = "approved" if approved else "denied"
            request.decided_at = time.time()
            request.decision_reason = (reason or "").strip()
            decision = "approved" if approved else "denied"
            self.progress.append(
                {"timestamp": time.time(), "message": f"Tool request {decision}: {request_id}"}
            )
            self.updated_at = time.time()
            self._condition.notify_all()

    def snapshot(self) -> dict[str, Any]:
        with self._condition:
            return {
                "run_id": self.run_id,
                "event_id": self.event_id,
                "analysis_types": list(self.analysis_types),
                "constraints": self.constraints,
                "provider": self.provider,
                "model": self.model,
                "approval_mode": self.approval_mode,
                "approval_provider": self.approval_provider,
                "approval_model": self.approval_model,
                "escalate_smart_rejections": self.escalate_smart_rejections,
                "status": self.status,
                "progress": list(self.progress),
                "tool_requests": [
                    request.to_dict()
                    for request in sorted(
                        self.tool_requests.values(),
                        key=lambda item: item.created_at,
                    )
                ],
                "pending_tool_requests": [
                    request.to_dict()
                    for request in sorted(
                        self.tool_requests.values(),
                        key=lambda item: item.created_at,
                    )
                    if request.status == "pending"
                ],
                "active_tool_execution": (
                    self.active_tool_execution.to_dict()
                    if self.active_tool_execution is not None
                    else None
                ),
                "result_markdown": self.result_markdown,
                "error": self.error,
                "created_at": self.created_at,
                "updated_at": self.updated_at,
            }


class AnalysisSessionStore:
    def __init__(self) -> None:
        self._runs: dict[str, AnalysisRun] = {}
        self._lock = threading.RLock()

    def create(
        self,
        *,
        event_id: int,
        analysis_types: list[str],
        constraints: str,
        provider: str,
        model: str,
        approval_timeout_seconds: float,
        approval_mode: str = APPROVAL_MODE_MANUAL,
        approval_provider: Optional[str] = None,
        approval_model: Optional[str] = None,
        escalate_smart_rejections: bool = True,
    ) -> AnalysisRun:
        run = AnalysisRun(
            event_id=event_id,
            analysis_types=analysis_types,
            constraints=constraints,
            provider=provider,
            model=model,
            approval_timeout_seconds=approval_timeout_seconds,
            approval_mode=approval_mode,
            approval_provider=approval_provider,
            approval_model=approval_model,
            escalate_smart_rejections=escalate_smart_rejections,
        )
        with self._lock:
            self._runs[run.run_id] = run
        return run

    def get(self, run_id: str) -> Optional[AnalysisRun]:
        with self._lock:
            return self._runs.get(run_id)


def _is_approving_decision(decision: Optional[dict[str, Any]]) -> bool:
    return bool(
        decision
        and decision.get("approved")
        and not decision.get("error")
    )


def _smart_rejection_reason(decision: Optional[dict[str, Any]]) -> str:
    """Reason string returned to the analysis LLM for a smart-approver rejection."""
    reasoning = str((decision or {}).get("reasoning") or "").strip()
    if reasoning:
        return reasoning
    if decision is None or decision.get("error"):
        return "The smart approver could not evaluate the tool call."
    return "The smart approver rejected the tool call."


def _smart_review_rejection_message(
    tool_name: str, decision: Optional[dict[str, Any]]
) -> str:
    reasoning = str((decision or {}).get("reasoning") or "").strip()
    if decision is None or decision.get("error"):
        prefix = f"Smart approver could not evaluate {tool_name}"
    else:
        prefix = f"Smart approver rejected {tool_name}"
    return prefix + (f": {reasoning}" if reasoning else ".")


def _manual_denial_reason(request: ToolApprovalRequest) -> str:
    """Reason returned to the analysis LLM when a call is denied in manual review."""
    user_reason = (request.decision_reason or "").strip()
    if user_reason:
        return user_reason
    review = request.smart_review
    if review and not _is_approving_decision(review):
        reasoning = str(review.get("reasoning") or "").strip()
        if reasoning:
            return f"Denied in manual review (smart approver note: {reasoning})"
    return "The tool call was denied in manual review."


def _is_mcp_database_tool_call(tool_call: dict[str, Any]) -> bool:
    server_id = str(tool_call.get("server_id") or "").strip().lower()
    server_label = str(tool_call.get("server_label") or "").strip().lower()
    return server_id in {"packet", "packet_db", "mcp_packet_db"} or server_label == "packet db"


def _tool_display_name(tool_call: dict[str, Any]) -> str:
    return str(tool_call.get("exposed_tool_name") or tool_call.get("tool_name") or "MCP tool")
