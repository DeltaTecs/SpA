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

from llm.provider.base import BaseProvider, ChatResult  # noqa: E402

from app.config import settings  # noqa: E402
from app.jobs.runner import run_exchange, store  # noqa: E402
from app.jobs.store import JobStore, derived_status  # noqa: E402
from app.schemas import Exchange, TaskResult  # noqa: E402
from app.tasks.base import AnalysisTask  # noqa: E402


class _StubProvider(BaseProvider):
    name = "stub"

    def __init__(self, content="final answer", *, raises=False):
        super().__init__(api_key=None, model="stub-model")
        self._content = content
        self._raises = raises

    def chat(self, messages, tools=None):
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


if __name__ == "__main__":
    unittest.main()
