"""Composable :class:`~llm.client.Toolset` wrappers for cost control.

Each wrapper decorates an inner toolset and itself satisfies the structural
``Toolset`` surface the orchestrator needs (``name``, ``list_tool_specs()``,
``call_tool()``), so they compose freely and require no changes to
:class:`~llm.client.McpLlmClient` or :class:`~llm.mcp.toolset.McpToolset`.

* :class:`PolicyToolset` - restrict which tools are advertised and rewrite a
  call's arguments before dispatch (e.g. clamp to cheaper parameters).
* :class:`CachingToolset` - serve repeat calls from a :class:`CacheBackend`.
* :class:`BudgetToolset` - stop dispatching once a :class:`CallBudget` is spent.

Wrap from the inside out as ``Policy(Caching(Budget(real)))`` so that argument
normalisation happens first (improving cache hit-rate) and only genuine cache
misses count against the budget.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Callable, Iterable

from ..provider.base import ToolSpec
from .budget import CallBudget
from .cache import CacheBackend, make_cache_key

if TYPE_CHECKING:  # avoid importing the higher-level client at runtime
    from ..client import Toolset

logger = logging.getLogger(__name__)

#: A transform applied to a call's ``(tool_name, arguments)`` before dispatch.
ArgTransform = Callable[[str, dict], dict]


class PolicyToolset:
    """Restrict advertised tools and rewrite call arguments before dispatch.

    ``allowed_tool_names`` (when given) filters the inner toolset's advertised
    specs so the model never sees - and therefore cannot call - tools outside
    the set. ``transform_args`` is applied to every call's arguments before they
    reach the inner toolset; use it to clamp parameters to cheaper values. The
    transformed arguments are what the inner (and any caching layer below) see,
    so normalising here also improves cache hit-rates.
    """

    def __init__(
        self,
        inner: "Toolset",
        *,
        transform_args: ArgTransform | None = None,
        allowed_tool_names: Iterable[str] | None = None,
        name: str | None = None,
    ) -> None:
        self._inner = inner
        self._transform_args = transform_args
        self._allowed = (
            set(allowed_tool_names) if allowed_tool_names is not None else None
        )
        self.name = name or getattr(inner, "name", "policy")

    def list_tool_specs(self) -> list[ToolSpec]:
        specs = self._inner.list_tool_specs()
        if self._allowed is None:
            return specs
        kept = [spec for spec in specs if spec.name in self._allowed]
        hidden = [spec.name for spec in specs if spec.name not in self._allowed]
        if hidden:
            logger.info(
                "Toolset '%s' hiding %d tool(s) by policy: %s",
                self.name,
                len(hidden),
                hidden,
            )
        return kept

    def call_tool(self, name: str, arguments: dict) -> str:
        if self._allowed is not None and name not in self._allowed:
            logger.warning(
                "Blocked call to disallowed tool '%s' on toolset '%s'", name, self.name
            )
            return f"Error: tool '{name}' is not available."
        if self._transform_args is not None:
            arguments = self._transform_args(name, dict(arguments))
        return self._inner.call_tool(name, arguments)


class CachingToolset:
    """Serve repeat tool calls from a cache, only dispatching on a miss.

    The cache key spans ``key_namespace`` (defaults to the inner toolset name),
    the tool name and the canonicalised arguments. Only successful results are
    cached - if the inner ``call_tool`` raises, the error propagates and nothing
    is stored.
    """

    def __init__(
        self,
        inner: "Toolset",
        cache: CacheBackend,
        *,
        key_namespace: str | None = None,
        name: str | None = None,
    ) -> None:
        self._inner = inner
        self._cache = cache
        self._namespace = key_namespace or getattr(inner, "name", "toolset")
        self.name = name or getattr(inner, "name", "cached")

    def list_tool_specs(self) -> list[ToolSpec]:
        return self._inner.list_tool_specs()

    def call_tool(self, name: str, arguments: dict) -> str:
        key = make_cache_key(self._namespace, name, arguments)
        cached = self._cache.get(key)
        if cached is not None:
            logger.info("Cache hit for tool '%s' on toolset '%s'", name, self.name)
            return cached
        logger.info("Cache miss for tool '%s' on toolset '%s'", name, self.name)
        result = self._inner.call_tool(name, arguments)
        self._cache.set(key, result)
        return result


class BudgetToolset:
    """Stop dispatching once a shared :class:`CallBudget` is exhausted.

    Each dispatched call consumes one unit. When the budget is spent the call is
    not forwarded; instead a short note is returned to the model so it relies on
    results already gathered. A ``None`` budget (or an unlimited one) is a pure
    pass-through.
    """

    #: Returned to the model in place of a tool result once the budget is spent.
    EXHAUSTED_NOTE = (
        "Search budget reached for this job; do not attempt further web "
        "searches - rely on the findings already gathered."
    )

    def __init__(
        self,
        inner: "Toolset",
        budget: CallBudget | None = None,
        *,
        name: str | None = None,
    ) -> None:
        self._inner = inner
        self._budget = budget
        self.name = name or getattr(inner, "name", "budgeted")

    def list_tool_specs(self) -> list[ToolSpec]:
        return self._inner.list_tool_specs()

    def call_tool(self, name: str, arguments: dict) -> str:
        if self._budget is not None and not self._budget.try_consume():
            logger.info(
                "Budget exhausted; blocking tool '%s' on toolset '%s'", name, self.name
            )
            return self.EXHAUSTED_NOTE
        return self._inner.call_tool(name, arguments)
