"""Tests for the scanner-backend provider catalogue."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.providers import list_providers, validate_reasoning_effort  # noqa: E402


class ProviderCatalogueTests(unittest.TestCase):
    def test_deepseek_v4_models_are_listed(self):
        providers = {provider.type: provider for provider in list_providers()}
        deepseek = providers["deepseek"]

        self.assertEqual(deepseek.default_model, "deepseek-v4-flash")
        self.assertIn("deepseek-v4-flash", deepseek.model_options)
        self.assertIn("deepseek-v4-pro", deepseek.model_options)
        self.assertEqual(deepseek.reasoning_effort_options, ["high", "max"])

    def test_rejects_unsupported_reasoning_effort(self):
        with self.assertRaises(ValueError):
            validate_reasoning_effort("local", "high")

        validate_reasoning_effort("deepseek", "max")
        validate_reasoning_effort("local", None)


if __name__ == "__main__":
    unittest.main()
