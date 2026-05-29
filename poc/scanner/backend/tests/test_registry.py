"""Tests for the analysis-task registry and the built-in task registration."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.tasks import available, get, register  # noqa: E402
from app.tasks.base import AnalysisTask  # noqa: E402
from app.schemas import Exchange, TaskResult  # noqa: E402


class _ValidTask(AnalysisTask):
    task_type = "unit_test_task"
    title = "Unit test task"
    description = "registered by the test"

    def build_system_prompt(self):
        return "sys"

    def build_user_prompt(self, exchange: Exchange):
        return "user"

    def parse_output(self, raw: str):
        return TaskResult(task_type=self.task_type, result_version=1, payload={})


class RegistryTests(unittest.TestCase):
    def test_builtin_task_registered(self):
        task = get("vulnerability_checks")
        self.assertEqual(task.task_type, "vulnerability_checks")
        self.assertIn("vulnerability_checks", [t.task_type for t in available()])

    def test_unknown_task_raises_keyerror(self):
        with self.assertRaises(KeyError):
            get("does_not_exist")

    def test_register_and_lookup(self):
        register(_ValidTask)
        self.assertEqual(get("unit_test_task").task_type, "unit_test_task")

    def test_register_duplicate_raises(self):
        with self.assertRaises(ValueError):

            @register
            class _Dup(AnalysisTask):
                task_type = "vulnerability_checks"

                def build_system_prompt(self):
                    return ""

                def build_user_prompt(self, exchange):
                    return ""

                def parse_output(self, raw):
                    return TaskResult(task_type=self.task_type, result_version=1, payload={})

    def test_register_without_task_type_raises(self):
        with self.assertRaises(ValueError):

            @register
            class _NoType(AnalysisTask):
                def build_system_prompt(self):
                    return ""

                def build_user_prompt(self, exchange):
                    return ""

                def parse_output(self, raw):
                    return TaskResult(task_type="base", result_version=1, payload={})


if __name__ == "__main__":
    unittest.main()
