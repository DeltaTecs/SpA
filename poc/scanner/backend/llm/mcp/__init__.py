"""MCP toolset access for the LLM client.

Note: this sub-package is named ``mcp`` but is always imported as
``llm.mcp``; the installed MCP SDK is imported absolutely (``from mcp import
...``) and is not shadowed.
"""

from __future__ import annotations

from .budget import CallBudget
from .cache import (
    CacheBackend,
    InMemoryTTLCache,
    LayeredCache,
    SqliteCache,
    make_cache_key,
)
from .toolset import McpToolset
from .wrappers import BudgetToolset, CachingToolset, PolicyToolset

__all__ = [
    "McpToolset",
    "CallBudget",
    "CacheBackend",
    "InMemoryTTLCache",
    "SqliteCache",
    "LayeredCache",
    "make_cache_key",
    "BudgetToolset",
    "CachingToolset",
    "PolicyToolset",
]
