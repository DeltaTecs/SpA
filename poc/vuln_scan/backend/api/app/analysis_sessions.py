from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional


TERMINAL_STATUSES = {"completed", "failed", "aborted"}


@dataclass
class ToolApprovalRequest:
    request_id: str
    tool_call: dict[str, Any]
    status: str = "pending"
    created_at: float = field(default_factory=time.time)
    decided_at: Optional[float] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "status": self.status,
            "created_at": self.created_at,
            "decided_at": self.decided_at,
            "tool_call": self.tool_call,
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
        auto_approve_mcp_database_requests: bool = False,
        auto_approve_all_mcp_requests: bool = False,
    ):
        self.run_id = uuid.uuid4().hex
        self.event_id = event_id
        self.analysis_types = analysis_types
        self.constraints = constraints
        self.provider = provider
        self.model = model
        self.approval_timeout_seconds = approval_timeout_seconds
        self.auto_approve_mcp_database_requests = auto_approve_mcp_database_requests
        self.auto_approve_all_mcp_requests = auto_approve_all_mcp_requests
        self.status = "queued"
        self.progress: list[dict[str, Any]] = []
        self.tool_requests: dict[str, ToolApprovalRequest] = {}
        self.active_tool_execution: Optional[ActiveToolExecution] = None
        self.result_markdown = ""
        self.error: Optional[str] = None
        self.abort_requested = False
        self.created_at = time.time()
        self.updated_at = self.created_at
        self._condition = threading.Condition(threading.RLock())

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

    def request_tool_permission(self, tool_call: dict[str, Any]) -> bool:
        with self._condition:
            if self.abort_requested:
                return False

            request_id = uuid.uuid4().hex
            request = ToolApprovalRequest(request_id=request_id, tool_call=tool_call)
            self.tool_requests[request_id] = request

            auto_approval_reason = self._auto_approval_reason(tool_call)
            if auto_approval_reason:
                request.status = "approved"
                request.decided_at = time.time()
                self.progress.append(
                    {
                        "timestamp": time.time(),
                        "message": f"{auto_approval_reason} tool request auto-approved: {request_id}",
                    }
                )
                self.updated_at = time.time()
                self._condition.notify_all()
                return True

            self.status = "waiting_for_tool_approval"
            self.progress.append(
                {
                    "timestamp": time.time(),
                    "message": (
                        "Tool approval requested: "
                        f"{tool_call.get('exposed_tool_name') or tool_call.get('tool_name')}"
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
                            "message": f"Tool approval timed out: {request_id}",
                        }
                    )
                    self._condition.notify_all()
                    return False
                self._condition.wait(timeout=min(remaining, 5))

            if self.abort_requested:
                request.status = "aborted"
                request.decided_at = time.time()
                self._condition.notify_all()
                return False

            self.status = "running"
            self.updated_at = time.time()
            self._condition.notify_all()
            return request.status == "approved"

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

    def decide_tool_request(self, request_id: str, approved: bool) -> None:
        with self._condition:
            request = self.tool_requests.get(request_id)
            if request is None:
                raise KeyError(request_id)
            if request.status != "pending":
                raise ValueError(f"Tool request {request_id} is already {request.status}")
            request.status = "approved" if approved else "denied"
            request.decided_at = time.time()
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
                "auto_approve_mcp_database_requests": self.auto_approve_mcp_database_requests,
                "auto_approve_all_mcp_requests": self.auto_approve_all_mcp_requests,
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

    def _auto_approval_reason(self, tool_call: dict[str, Any]) -> Optional[str]:
        if self.auto_approve_all_mcp_requests:
            return "MCP"
        if self.auto_approve_mcp_database_requests and _is_mcp_database_tool_call(tool_call):
            return "MCP database"
        return None


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
        auto_approve_mcp_database_requests: bool = False,
        auto_approve_all_mcp_requests: bool = False,
    ) -> AnalysisRun:
        run = AnalysisRun(
            event_id=event_id,
            analysis_types=analysis_types,
            constraints=constraints,
            provider=provider,
            model=model,
            approval_timeout_seconds=approval_timeout_seconds,
            auto_approve_mcp_database_requests=auto_approve_mcp_database_requests,
            auto_approve_all_mcp_requests=auto_approve_all_mcp_requests,
        )
        with self._lock:
            self._runs[run.run_id] = run
        return run

    def get(self, run_id: str) -> Optional[AnalysisRun]:
        with self._lock:
            return self._runs.get(run_id)


def _is_mcp_database_tool_call(tool_call: dict[str, Any]) -> bool:
    server_id = str(tool_call.get("server_id") or "").strip().lower()
    server_label = str(tool_call.get("server_label") or "").strip().lower()
    return server_id in {"packet", "packet_db", "mcp_packet_db"} or server_label == "packet db"


def _tool_display_name(tool_call: dict[str, Any]) -> str:
    return str(tool_call.get("exposed_tool_name") or tool_call.get("tool_name") or "MCP tool")
