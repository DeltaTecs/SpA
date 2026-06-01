"""LLM / MCP client module.

Run a prompt against one or more MCP server toolsets using a configurable LLM
provider. Configure file logging once with :func:`configure_logging`.

Example::

    from llm import ProviderFactory, McpToolset, McpLlmClient, configure_logging

    configure_logging()
    provider = ProviderFactory.create("deepseek", api_key="sk-...")
    toolset = McpToolset("http://localhost:8765/mcp")
    result = McpLlmClient(provider, [toolset]).run("List packet IDs for recording 1.")
    print(result.output)
"""

from __future__ import annotations

from .cancellation import CancellationToken, OperationCancelled
from .client import ActivityReporter, McpLlmClient, RunResult, ToolApprover, ToolDecision
from .logging_config import configure_logging
from .mcp import (
    BudgetToolset,
    CacheBackend,
    CachingToolset,
    CallBudget,
    InMemoryTTLCache,
    LayeredCache,
    McpToolset,
    PolicyToolset,
    SqliteCache,
    make_cache_key,
)
from .provider import (
    BaseProvider,
    ChatMessage,
    ChatResult,
    DeepSeekProvider,
    LocalProvider,
    OpenAIProvider,
    ProviderFactory,
    ToolCall,
    ToolSpec,
)

__all__ = [
    "McpLlmClient",
    "RunResult",
    "ActivityReporter",
    "ToolApprover",
    "ToolDecision",
    "CancellationToken",
    "OperationCancelled",
    "McpToolset",
    "BudgetToolset",
    "CachingToolset",
    "PolicyToolset",
    "CallBudget",
    "CacheBackend",
    "InMemoryTTLCache",
    "SqliteCache",
    "LayeredCache",
    "make_cache_key",
    "ProviderFactory",
    "BaseProvider",
    "OpenAIProvider",
    "DeepSeekProvider",
    "LocalProvider",
    "ChatMessage",
    "ChatResult",
    "ToolCall",
    "ToolSpec",
    "configure_logging",
]
