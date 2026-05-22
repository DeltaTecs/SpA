from __future__ import annotations

import sys
import threading
import time
import unittest
from pathlib import Path


API_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(API_DIR))

from app.analysis_runs import (  # noqa: E402
    APPROVAL_MODE_AUTO_ALL,
    APPROVAL_MODE_AUTO_DB,
    APPROVAL_MODE_MANUAL,
    APPROVAL_MODE_SMART_NON_DB,
    AnalysisRun,
)


DB_CALL = {
    "server_id": "packet",
    "server_label": "Packet DB",
    "tool_name": "conversation_packets",
    "exposed_tool_name": "packet__conversation_packets",
    "arguments": {},
}
NON_DB_CALL = {
    "server_id": "hexstrike",
    "server_label": "HexStrike",
    "tool_name": "nmap_scan",
    "exposed_tool_name": "hexstrike__nmap_scan",
    "arguments": {"target": "example.com"},
}


def _make_run(
    approval_mode: str,
    *,
    approval_timeout_seconds: float = 5.0,
    escalate_smart_rejections: bool = True,
    max_reasoning_effort: bool = False,
    unlimited_rounds: bool = False,
    bash_mode: bool = False,
) -> AnalysisRun:
    return AnalysisRun(
        event_id=1,
        analysis_types=["Recon: Ports"],
        constraints="stay within the documented scope",
        provider="ollama",
        model="qwen3:8b",
        approval_timeout_seconds=approval_timeout_seconds,
        approval_mode=approval_mode,
        escalate_smart_rejections=escalate_smart_rejections,
        max_reasoning_effort=max_reasoning_effort,
        unlimited_rounds=unlimited_rounds,
        bash_mode=bash_mode,
    )


def _wait_for_pending_request(run: AnalysisRun, timeout: float = 5.0) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        pending = run.snapshot()["pending_tool_requests"]
        if pending:
            return pending[0]["request_id"]
        time.sleep(0.02)
    raise AssertionError("no pending tool request appeared")


def _decide_in_background(run: AnalysisRun, tool_call: dict) -> dict:
    """Request permission on a worker thread; return a dict the caller fills."""
    result: dict[str, tuple[bool, str]] = {}

    def worker() -> None:
        result["decision"] = run.request_tool_permission(tool_call)

    result["thread"] = threading.Thread(target=worker)  # type: ignore[assignment]
    result["thread"].start()  # type: ignore[union-attr]
    return result


class StaticApprovalModeTest(unittest.TestCase):
    def test_unknown_mode_falls_back_to_manual(self) -> None:
        run = _make_run("not-a-real-mode")
        self.assertEqual(run.approval_mode, APPROVAL_MODE_MANUAL)

    def test_snapshot_includes_phase_two_model_options(self) -> None:
        run = _make_run(
            APPROVAL_MODE_MANUAL,
            max_reasoning_effort=True,
            unlimited_rounds=True,
            bash_mode=True,
        )
        snapshot = run.snapshot()
        self.assertTrue(snapshot["max_reasoning_effort"])
        self.assertTrue(snapshot["unlimited_rounds"])
        self.assertTrue(snapshot["bash_mode"])

    def test_bash_mode_defaults_to_false(self) -> None:
        self.assertFalse(_make_run(APPROVAL_MODE_MANUAL).snapshot()["bash_mode"])

    def test_auto_all_approves_any_tool_without_blocking(self) -> None:
        run = _make_run(APPROVAL_MODE_AUTO_ALL)
        self.assertEqual(run.request_tool_permission(NON_DB_CALL), (True, ""))
        self.assertEqual(run.request_tool_permission(DB_CALL), (True, ""))

    def test_auto_db_approves_database_tools_only(self) -> None:
        run = _make_run(APPROVAL_MODE_AUTO_DB)
        self.assertEqual(run.request_tool_permission(DB_CALL), (True, ""))

    def test_auto_db_blocks_non_database_tools_until_decided(self) -> None:
        run = _make_run(APPROVAL_MODE_AUTO_DB)
        result = _decide_in_background(run, NON_DB_CALL)
        request_id = _wait_for_pending_request(run)
        run.decide_tool_request(request_id, True)
        result["thread"].join(timeout=5)  # type: ignore[union-attr]
        self.assertEqual(result["decision"], (True, ""))


class SmartApprovalModeTest(unittest.TestCase):
    def test_smart_mode_auto_approves_database_tools(self) -> None:
        run = _make_run(APPROVAL_MODE_SMART_NON_DB)
        run.attach_smart_reviewer(lambda _call: self.fail("db tool must skip review"))
        self.assertEqual(run.request_tool_permission(DB_CALL), (True, ""))

    def test_smart_mode_auto_approves_when_reviewer_approves(self) -> None:
        run = _make_run(APPROVAL_MODE_SMART_NON_DB)
        run.attach_smart_reviewer(
            lambda _call: {"approved": True, "reasoning": "within scope", "error": False}
        )
        self.assertEqual(run.request_tool_permission(NON_DB_CALL), (True, ""))

    def test_smart_rejection_without_escalation_is_final(self) -> None:
        run = _make_run(APPROVAL_MODE_SMART_NON_DB, escalate_smart_rejections=False)
        run.attach_smart_reviewer(
            lambda _call: {
                "approved": False,
                "reasoning": "destructive payload outside scope",
                "error": False,
            }
        )
        approved, reason = run.request_tool_permission(NON_DB_CALL)
        self.assertFalse(approved)
        self.assertEqual(reason, "destructive payload outside scope")

        denied = [
            request
            for request in run.snapshot()["tool_requests"]
            if request["status"] == "denied"
        ]
        self.assertEqual(len(denied), 1)
        self.assertFalse(denied[0]["smart_review"]["approved"])

    def test_smart_reviewer_error_without_escalation_returns_a_reason(self) -> None:
        run = _make_run(APPROVAL_MODE_SMART_NON_DB, escalate_smart_rejections=False)

        def failing_reviewer(_call: dict) -> dict:
            raise RuntimeError("reviewer unavailable")

        run.attach_smart_reviewer(failing_reviewer)
        approved, reason = run.request_tool_permission(NON_DB_CALL)
        self.assertFalse(approved)
        self.assertIn("could not evaluate", reason)

    def test_smart_rejection_with_escalation_falls_back_to_manual(self) -> None:
        run = _make_run(APPROVAL_MODE_SMART_NON_DB, escalate_smart_rejections=True)
        run.attach_smart_reviewer(
            lambda _call: {
                "approved": False,
                "reasoning": "out of scope",
                "error": False,
            }
        )
        result = _decide_in_background(run, NON_DB_CALL)
        request_id = _wait_for_pending_request(run)

        pending = run.snapshot()["pending_tool_requests"][0]
        self.assertIsNotNone(pending["smart_review"])
        self.assertIn("out of scope", pending["smart_review"]["reasoning"])

        run.decide_tool_request(request_id, True)
        result["thread"].join(timeout=5)  # type: ignore[union-attr]
        self.assertEqual(result["decision"], (True, ""))

    def test_escalated_then_denied_returns_smart_reason_to_llm(self) -> None:
        run = _make_run(APPROVAL_MODE_SMART_NON_DB, escalate_smart_rejections=True)
        run.attach_smart_reviewer(
            lambda _call: {
                "approved": False,
                "reasoning": "exceeds proof-of-vulnerability scope",
                "error": False,
            }
        )
        result = _decide_in_background(run, NON_DB_CALL)
        request_id = _wait_for_pending_request(run)
        run.decide_tool_request(request_id, False)
        result["thread"].join(timeout=5)  # type: ignore[union-attr]

        approved, reason = result["decision"]
        self.assertFalse(approved)
        self.assertIn("exceeds proof-of-vulnerability scope", reason)

    def test_smart_mode_without_reviewer_requires_manual_approval(self) -> None:
        run = _make_run(APPROVAL_MODE_SMART_NON_DB)
        result = _decide_in_background(run, NON_DB_CALL)
        request_id = _wait_for_pending_request(run)
        run.decide_tool_request(request_id, True)
        result["thread"].join(timeout=5)  # type: ignore[union-attr]
        self.assertEqual(result["decision"], (True, ""))


class ManualApprovalModeTest(unittest.TestCase):
    def test_manual_denial_returns_the_user_supplied_reason(self) -> None:
        run = _make_run(APPROVAL_MODE_MANUAL)
        result = _decide_in_background(run, DB_CALL)
        request_id = _wait_for_pending_request(run)
        run.decide_tool_request(request_id, False, "narrow the scanned port range")
        result["thread"].join(timeout=5)  # type: ignore[union-attr]

        approved, reason = result["decision"]
        self.assertFalse(approved)
        self.assertEqual(reason, "narrow the scanned port range")

    def test_manual_denial_without_reason_still_returns_a_reason(self) -> None:
        run = _make_run(APPROVAL_MODE_MANUAL)
        result = _decide_in_background(run, DB_CALL)
        request_id = _wait_for_pending_request(run)
        run.decide_tool_request(request_id, False)
        result["thread"].join(timeout=5)  # type: ignore[union-attr]

        approved, reason = result["decision"]
        self.assertFalse(approved)
        self.assertTrue(reason.strip())

    def test_approval_timeout_returns_a_reason(self) -> None:
        run = _make_run(APPROVAL_MODE_MANUAL, approval_timeout_seconds=0.2)
        approved, reason = run.request_tool_permission(DB_CALL)
        self.assertFalse(approved)
        self.assertIn("timed out", reason)

    def test_abort_aborts_pending_tool_request_and_unblocks_waiter(self) -> None:
        run = _make_run(APPROVAL_MODE_MANUAL)
        result = _decide_in_background(run, NON_DB_CALL)
        request_id = _wait_for_pending_request(run)

        run.abort()
        result["thread"].join(timeout=5)  # type: ignore[union-attr]

        approved, reason = result["decision"]
        self.assertFalse(approved)
        self.assertIn("aborted", reason)

        snapshot = run.snapshot()
        self.assertEqual(snapshot["status"], "aborted")
        self.assertEqual(snapshot["pending_tool_requests"], [])
        requests = {
            request["request_id"]: request
            for request in snapshot["tool_requests"]
        }
        self.assertEqual(requests[request_id]["status"], "aborted")

    def test_abort_requests_active_tool_stop(self) -> None:
        run = _make_run(APPROVAL_MODE_MANUAL)
        execution_id = run.start_tool_execution(NON_DB_CALL)

        run.abort()

        snapshot = run.snapshot()
        self.assertEqual(snapshot["status"], "aborted")
        self.assertEqual(
            snapshot["active_tool_execution"]["status"],
            "stop_requested",
        )
        self.assertTrue(run.is_tool_stop_requested(execution_id))

    def test_tool_started_after_abort_is_immediately_stop_requested(self) -> None:
        run = _make_run(APPROVAL_MODE_AUTO_ALL)
        run.abort()

        execution_id = run.start_tool_execution(NON_DB_CALL)

        snapshot = run.snapshot()
        self.assertEqual(
            snapshot["active_tool_execution"]["status"],
            "stop_requested",
        )
        self.assertTrue(run.is_tool_stop_requested(execution_id))

    def test_abort_invokes_registered_abort_callback(self) -> None:
        run = _make_run(APPROVAL_MODE_MANUAL)
        calls: list[str] = []

        run.register_abort_callback(lambda: calls.append("cancelled"))
        run.abort()

        self.assertEqual(calls, ["cancelled"])

    def test_unregistered_abort_callback_is_not_invoked(self) -> None:
        run = _make_run(APPROVAL_MODE_MANUAL)
        calls: list[str] = []

        callback = lambda: calls.append("cancelled")
        run.register_abort_callback(callback)
        run.unregister_abort_callback(callback)
        run.abort()

        self.assertEqual(calls, [])

    def test_register_abort_callback_after_abort_invokes_immediately(self) -> None:
        run = _make_run(APPROVAL_MODE_MANUAL)
        calls: list[str] = []

        run.abort()
        run.register_abort_callback(lambda: calls.append("cancelled"))

        self.assertEqual(calls, ["cancelled"])


if __name__ == "__main__":
    unittest.main()
