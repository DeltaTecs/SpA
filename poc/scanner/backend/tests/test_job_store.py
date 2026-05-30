"""Tests for the in-memory job store and the task-agnostic worker body.

Uses a stub provider and a trivial fake task (no network, no MCP), which also
demonstrates that the runner only depends on the AnalysisTask contract.
"""

from __future__ import annotations

import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from llm.provider.base import BaseProvider, ChatResult, ToolCall, ToolSpec  # noqa: E402

from app.config import settings  # noqa: E402
from app.jobs.runner import run_exchange, store  # noqa: E402
from app.jobs.store import JobStore, derived_status  # noqa: E402
from app.schemas import Exchange, TaskResult  # noqa: E402
from app.tasks.base import AnalysisTask, TaskPromptPart  # noqa: E402


class _StubProvider(BaseProvider):
    name = "stub"

    def __init__(self, content="final answer", *, raises=False):
        super().__init__(api_key=None, model="stub-model")
        self._content = content
        self._raises = raises
        self.messages = []

    def chat(self, messages, tools=None):
        self.messages = list(messages)
        if self._raises:
            raise RuntimeError("provider boom")
        return ChatResult(content=self._content)


class _EchoTask(AnalysisTask):
    task_type = "echo"
    title = "Echo"
    description = "fake task for tests"

    def build_system_prompt(self):
        return "system"

    def build_user_prompt(self, exchange: Exchange):
        return f"user:{exchange.id}"

    def select_toolsets(self, cfg):
        return []  # no MCP toolsets -> no network

    def parse_output(self, raw: str):
        return TaskResult(task_type=self.task_type, result_version=1, payload={"raw": raw})


class _OverrideTask(_EchoTask):
    def prompt_parts(self):
        return [
            TaskPromptPart(
                id="system_prompt",
                title="System prompt",
                scope="system",
                content="default system",
            ),
            TaskPromptPart(
                id="user_prompt",
                title="User prompt",
                scope="user",
                content="default user",
            ),
        ]

    def build_system_prompt_for_run(self, prompt_overrides=None):
        return (prompt_overrides or {}).get("system_prompt", "default system")

    def build_user_prompt_for_run(self, exchange: Exchange, prompt_overrides=None):
        return (prompt_overrides or {}).get("user_prompt", "default user")


class _ToolThenAnswerProvider(BaseProvider):
    """Requests one tool call on the first turn, then returns a final answer."""

    name = "tooler"

    def __init__(self):
        super().__init__(api_key=None, model="m")
        self.turns = 0

    def chat(self, messages, tools=None):
        self.turns += 1
        if self.turns == 1:
            return ChatResult(tool_calls=[ToolCall(id="c1", name="lookup", arguments={})])
        return ChatResult(content="done")


class _CancellingToolset:
    """A toolset that runs a side effect (e.g. cancel the job) when called."""

    name = "fake"

    def __init__(self, on_call):
        self._on_call = on_call
        self.calls = []

    def list_tool_specs(self):
        return [ToolSpec(name="lookup", description="d", parameters={"type": "object"})]

    def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        self._on_call()
        return "out"


class _ToolTask(_EchoTask):
    def __init__(self, toolset):
        self._toolset = toolset

    def select_toolsets(self, cfg):
        return [self._toolset]


class JobStoreTests(unittest.TestCase):
    def test_create_and_get_returns_pending_tasks(self):
        s = JobStore()
        job_id = s.create(
            provider="local",
            model="m",
            reasoning_effort=None,
            task_type="echo",
            exchange_ids=["a", "b"],
        )
        job = s.get(job_id)
        self.assertEqual([t.exchange_id for t in job.tasks], ["a", "b"])
        self.assertTrue(all(t.status == "pending" for t in job.tasks))
        self.assertEqual(derived_status(job.tasks), "running")

    def test_get_returns_isolated_copy(self):
        s = JobStore()
        job_id = s.create(
            provider="local",
            model="m",
            reasoning_effort=None,
            task_type="echo",
            exchange_ids=["a"],
        )
        snapshot = s.get(job_id)
        snapshot.tasks[0].status = "done"  # mutate the copy
        self.assertEqual(s.get(job_id).tasks[0].status, "pending")  # store unaffected

    def test_update_task(self):
        s = JobStore()
        job_id = s.create(
            provider="local",
            model="m",
            reasoning_effort=None,
            task_type="echo",
            exchange_ids=["a"],
        )
        s.update_task(job_id, "a", status="done", result={"x": 1})
        job = s.get(job_id)
        self.assertEqual(job.tasks[0].status, "done")
        self.assertEqual(job.tasks[0].result, {"x": 1})
        self.assertEqual(derived_status(job.tasks), "done")


class RunExchangeTests(unittest.TestCase):
    def test_success_records_done_result(self):
        job_id = store.create(
            provider="local",
            model="m",
            reasoning_effort=None,
            task_type="echo",
            exchange_ids=["e1"],
        )
        run_exchange(job_id, Exchange(id="e1"), _EchoTask(), _StubProvider("hi"), 5, settings)
        task = store.get(job_id).tasks[0]
        self.assertEqual(task.status, "done")
        self.assertEqual(task.result["payload"]["raw"], "hi")
        self.assertEqual(task.iterations, 1)

    def test_failure_records_error(self):
        job_id = store.create(
            provider="local",
            model="m",
            reasoning_effort=None,
            task_type="echo",
            exchange_ids=["e1"],
        )
        run_exchange(job_id, Exchange(id="e1"), _EchoTask(), _StubProvider(raises=True), 5, settings)
        task = store.get(job_id).tasks[0]
        self.assertEqual(task.status, "error")
        self.assertIn("provider boom", task.error)

    def test_prompt_overrides_are_sent_to_provider(self):
        job_id = store.create(
            provider="local",
            model="m",
            reasoning_effort=None,
            task_type="echo",
            exchange_ids=["e1"],
        )
        provider = _StubProvider("hi")
        run_exchange(
            job_id,
            Exchange(id="e1"),
            _OverrideTask(),
            provider,
            5,
            settings,
            {"system_prompt": "custom system", "user_prompt": "custom user"},
        )
        self.assertEqual(provider.messages[0].role, "system")
        self.assertEqual(provider.messages[0].content, "custom system")
        self.assertEqual(provider.messages[1].role, "user")
        self.assertEqual(provider.messages[1].content, "custom user")

    def test_concurrent_runs_all_complete(self):
        ids = [f"e{i}" for i in range(8)]
        job_id = store.create(
            provider="local",
            model="m",
            reasoning_effort=None,
            task_type="echo",
            exchange_ids=ids,
        )
        task = _EchoTask()
        provider = _StubProvider("ok")
        threads = [
            threading.Thread(
                target=run_exchange, args=(job_id, Exchange(id=eid), task, provider, 5, settings)
            )
            for eid in ids
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        job = store.get(job_id)
        self.assertTrue(all(t.status == "done" for t in job.tasks))
        self.assertEqual(derived_status(job.tasks), "done")


class JobCancellationTests(unittest.TestCase):
    def _job(self, s, ids=("a", "b")):
        return s.create(
            provider="local",
            model="m",
            reasoning_effort=None,
            task_type="echo",
            exchange_ids=list(ids),
        )

    def test_cancel_marks_inflight_and_sets_token(self):
        s = JobStore()
        job_id = self._job(s)
        s.update_task(job_id, "a", status="running")
        self.assertTrue(s.cancel(job_id))
        job = s.get(job_id)
        self.assertEqual([t.status for t in job.tasks], ["cancelled", "cancelled"])
        self.assertEqual(derived_status(job.tasks), "cancelled")
        self.assertTrue(s.token_for(job_id).is_cancelled)

    def test_cancel_keeps_finished_outcomes(self):
        s = JobStore()
        job_id = self._job(s)
        s.update_task(job_id, "a", status="done", result={"x": 1})
        s.cancel(job_id)
        statuses = {t.exchange_id: t.status for t in s.get(job_id).tasks}
        self.assertEqual(statuses, {"a": "done", "b": "cancelled"})

    def test_update_task_frozen_after_cancel(self):
        s = JobStore()
        job_id = self._job(s, ids=("a",))
        s.cancel(job_id)
        s.update_task(job_id, "a", status="done", result={"x": 1})  # late worker write
        self.assertEqual(s.get(job_id).tasks[0].status, "cancelled")

    def test_cancel_unknown_returns_false(self):
        self.assertFalse(JobStore().cancel("nope"))


class RunExchangeCancellationTests(unittest.TestCase):
    def test_skips_when_cancelled_before_start(self):
        job_id = store.create(
            provider="local",
            model="m",
            reasoning_effort=None,
            task_type="echo",
            exchange_ids=["e1"],
        )
        store.cancel(job_id)
        run_exchange(job_id, Exchange(id="e1"), _EchoTask(), _StubProvider("hi"), 5, settings)
        self.assertEqual(store.get(job_id).tasks[0].status, "cancelled")

    def test_midrun_cancellation_records_cancelled(self):
        job_id = store.create(
            provider="local",
            model="m",
            reasoning_effort=None,
            task_type="echo",
            exchange_ids=["e1"],
        )
        toolset = _CancellingToolset(lambda: store.cancel(job_id))
        run_exchange(
            job_id, Exchange(id="e1"), _ToolTask(toolset), _ToolThenAnswerProvider(), 5, settings
        )
        self.assertEqual(store.get(job_id).tasks[0].status, "cancelled")
        self.assertEqual(len(toolset.calls), 1)  # stopped before a second tool call


if __name__ == "__main__":
    unittest.main()
