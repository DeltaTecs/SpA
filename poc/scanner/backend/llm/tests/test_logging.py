"""Tests that configure_logging writes a populated log file."""

from __future__ import annotations

import logging
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from llm import logging_config  # noqa: E402


class TestLoggingConfig(unittest.TestCase):
    def setUp(self):
        self._root = logging.getLogger()
        self._saved_handlers = list(self._root.handlers)
        self._saved_level = self._root.level
        self._saved_configured = logging_config._configured
        self._saved_env = os.environ.get("LLM_LOG_DIR")
        self._tmp = tempfile.TemporaryDirectory()
        os.environ["LLM_LOG_DIR"] = self._tmp.name
        logging_config._configured = False

    def tearDown(self):
        # Restore root logger to its pre-test state so other tests are unaffected.
        for handler in list(self._root.handlers):
            handler.close()
            self._root.removeHandler(handler)
        for handler in self._saved_handlers:
            self._root.addHandler(handler)
        self._root.setLevel(self._saved_level)
        logging_config._configured = self._saved_configured
        if self._saved_env is None:
            os.environ.pop("LLM_LOG_DIR", None)
        else:
            os.environ["LLM_LOG_DIR"] = self._saved_env
        self._tmp.cleanup()

    def test_creates_and_writes_log_file(self):
        log_file = logging_config.configure_logging(force=True)
        self.assertEqual(log_file.parent, Path(self._tmp.name))

        logging.getLogger("llm.test").info("hello from the logging test")
        for handler in logging.getLogger().handlers:
            handler.flush()

        self.assertTrue(log_file.exists())
        contents = log_file.read_text(encoding="utf-8")
        self.assertIn("hello from the logging test", contents)

    def test_idempotent_without_force(self):
        logging_config.configure_logging(force=True)
        handler_count = len(logging.getLogger().handlers)
        logging_config.configure_logging()  # no force -> no-op
        self.assertEqual(len(logging.getLogger().handlers), handler_count)


if __name__ == "__main__":
    unittest.main()
