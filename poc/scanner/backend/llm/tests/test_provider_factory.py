"""Tests for ProviderFactory."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from llm.provider import (  # noqa: E402
    DeepSeekProvider,
    LocalProvider,
    OpenAIProvider,
    ProviderFactory,
)
from llm.provider.deepseek_provider import DEFAULT_BASE_URL as DEEPSEEK_BASE_URL  # noqa: E402


class TestProviderFactory(unittest.TestCase):
    def test_creates_openai_provider_with_key(self):
        provider = ProviderFactory.create("openai", api_key="sk-test")
        self.assertIsInstance(provider, OpenAIProvider)
        self.assertEqual(provider.api_key, "sk-test")
        self.assertEqual(provider.model, "gpt-4o-mini")

    def test_creates_deepseek_provider_with_defaults(self):
        provider = ProviderFactory.create("deepseek", api_key="sk-test")
        self.assertIsInstance(provider, DeepSeekProvider)
        self.assertEqual(provider.model, "deepseek-v4-flash")
        self.assertEqual(provider.base_url, DEEPSEEK_BASE_URL)

    def test_case_insensitive_type(self):
        provider = ProviderFactory.create("OpenAI", api_key="sk-test")
        self.assertIsInstance(provider, OpenAIProvider)

    def test_model_override(self):
        provider = ProviderFactory.create("openai", api_key="sk-test", model="gpt-4o")
        self.assertEqual(provider.model, "gpt-4o")

    def test_reasoning_effort_override(self):
        provider = ProviderFactory.create(
            "deepseek",
            api_key="sk-test",
            model="deepseek-v4-pro",
            reasoning_effort="max",
        )
        self.assertEqual(provider.reasoning_effort, "max")

    def test_keyed_provider_requires_key(self):
        with self.assertRaises(ValueError):
            ProviderFactory.create("openai")
        with self.assertRaises(ValueError):
            ProviderFactory.create("deepseek", api_key="   ")

    def test_local_provider_needs_no_key(self):
        provider = ProviderFactory.create("local")
        self.assertIsInstance(provider, LocalProvider)
        self.assertIsNone(provider.api_key)

    def test_qwen_alias_maps_to_local(self):
        provider = ProviderFactory.create("qwen")
        self.assertIsInstance(provider, LocalProvider)

    def test_unknown_type_raises(self):
        with self.assertRaises(ValueError):
            ProviderFactory.create("not-a-provider", api_key="x")

    def test_supported_types(self):
        types = ProviderFactory.supported_types()
        self.assertIn("openai", types)
        self.assertIn("deepseek", types)
        self.assertIn("local", types)


if __name__ == "__main__":
    unittest.main()
