"""MCP toolset access for the LLM client.

Note: this sub-package is named ``mcp`` but is always imported as
``llm.mcp``; the installed MCP SDK is imported absolutely (``from mcp import
...``) and is not shadowed.
"""

from __future__ import annotations

from .toolset import McpToolset

__all__ = ["McpToolset"]
