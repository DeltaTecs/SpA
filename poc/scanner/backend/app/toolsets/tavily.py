"""Assembly of the cost-controlled Tavily web-search toolset.

Wraps the raw Tavily MCP :class:`~llm.McpToolset` with the generic cost-control
wrappers (:mod:`llm.mcp.wrappers`) using Tavily-specific policy:

* **clamp + normalise** search parameters to cheaper values (basic depth,
  capped results, no raw content) - this both lowers per-call credits and makes
  cache keys collide more often,
* **hide expensive tools** (``tavily_crawl`` off by default),
* **cache** responses process-wide (memory + optional persistent SQLite), and
* honour an optional **per-job call budget**.

Tavily knowledge lives here so the ``llm`` library stays domain-agnostic. The
response cache is a process-wide singleton (built once from settings, like the
job store in :mod:`app.jobs.runner`); tests may inject their own cache instead.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Optional

from llm import (
    BudgetToolset,
    CacheBackend,
    CachingToolset,
    CallBudget,
    InMemoryTTLCache,
    LayeredCache,
    McpToolset,
    PolicyToolset,
    SqliteCache,
)
from llm.client import Toolset

from ..config import Settings

logger = logging.getLogger(__name__)

#: Stable label used for the toolset and its cache-key namespace.
TAVILY_TOOLSET_NAME = "tavily"

_cache: Optional[CacheBackend] = None
_cache_lock = threading.Lock()


def tavily_allowed_tools(settings: Settings) -> set[str]:
    """The Tavily tool names the model may use, per cost policy.

    ``tavily_search`` is always allowed; ``tavily_extract`` and the expensive
    ``tavily_crawl`` are opt-in via settings (crawl off by default).
    """
    allowed = {"tavily_search"}
    if settings.tavily_allow_extract:
        allowed.add("tavily_extract")
    if settings.tavily_allow_crawl:
        allowed.add("tavily_crawl")
    return allowed


def clamp_tavily_args(
    settings: Settings, name: str, arguments: dict[str, Any]
) -> dict[str, Any]:
    """Rewrite a Tavily call's arguments to cheaper, normalised values.

    For ``tavily_search``: force ``search_depth`` to the configured value (basic
    = 1 credit vs advanced = 2) and cap ``max_results``. For every tool: drop
    ``include_raw_content`` unless explicitly enabled. Other keys pass through
    untouched so the model keeps full control of the actual query.
    """
    args = dict(arguments)
    if name == "tavily_search":
        args["search_depth"] = settings.tavily_search_depth
        if settings.tavily_max_results > 0:
            requested = args.get("max_results")
            if not isinstance(requested, int) or requested > settings.tavily_max_results:
                args["max_results"] = settings.tavily_max_results
    if not settings.tavily_include_raw_content:
        args.pop("include_raw_content", None)
    return args


def _build_cache(settings: Settings) -> CacheBackend:
    """Build the cache tier(s): in-memory always, persistent SQLite if a path is set."""
    backends: list[CacheBackend] = [
        InMemoryTTLCache(
            ttl_seconds=settings.tavily_cache_ttl_seconds,
            max_entries=settings.tavily_cache_max_entries,
        )
    ]
    if settings.tavily_cache_path:
        try:
            backends.append(
                SqliteCache(
                    settings.tavily_cache_path,
                    ttl_seconds=settings.tavily_cache_ttl_seconds,
                )
            )
        except Exception:  # noqa: BLE001 - never let a cache FS error break analysis
            logger.exception(
                "Could not open Tavily SQLite cache at %s; using memory only",
                settings.tavily_cache_path,
            )
    return backends[0] if len(backends) == 1 else LayeredCache(backends)


def get_tavily_cache(settings: Settings) -> Optional[CacheBackend]:
    """Return the process-wide Tavily response cache (built once), or ``None``.

    Returns ``None`` when caching is disabled. The first successful build is
    memoised for the lifetime of the process; later calls ignore ``settings``.
    """
    global _cache
    if not settings.tavily_cache_enabled:
        return None
    if _cache is None:
        with _cache_lock:
            if _cache is None:
                _cache = _build_cache(settings)
    return _cache


def build_tavily_toolset(
    settings: Settings,
    *,
    budget: CallBudget | None = None,
    cache: CacheBackend | None = None,
    restrict_tools: bool = True,
) -> Toolset:
    """Build the cost-controlled Tavily toolset stack.

    Layering (outer -> inner): policy (clamp args, optionally hide tools) ->
    caching -> budget -> the real Tavily MCP toolset. Returns a single object
    satisfying the orchestrator's :class:`~llm.client.Toolset` surface.

    Argument clamping, caching and the optional budget always apply.
    ``restrict_tools`` controls only *tool hiding*: when ``True`` (analysis
    flow) the advertised tools are limited to :func:`tavily_allowed_tools`; when
    ``False`` (interactive pentest/exploit/guided flows) every Tavily tool is
    advertised and the operator's catalogue selection governs availability.

    ``cache`` overrides the process-wide singleton (used by tests); ``budget``
    enforces a per-job ceiling (omit or pass an unlimited budget to disable).
    """
    if not settings.tavily_url:
        raise ValueError("Tavily is not configured (no TAVILY_API_KEY)")

    toolset: Toolset = McpToolset(
        settings.tavily_url, name=TAVILY_TOOLSET_NAME, timeout=settings.mcp_timeout
    )

    if budget is not None and not budget.unlimited:
        toolset = BudgetToolset(toolset, budget, name=TAVILY_TOOLSET_NAME)

    if cache is None:
        cache = get_tavily_cache(settings)
    if cache is not None:
        toolset = CachingToolset(
            toolset, cache, key_namespace=TAVILY_TOOLSET_NAME, name=TAVILY_TOOLSET_NAME
        )

    return PolicyToolset(
        toolset,
        transform_args=lambda tool_name, args: clamp_tavily_args(
            settings, tool_name, args
        ),
        allowed_tool_names=tavily_allowed_tools(settings) if restrict_tools else None,
        name=TAVILY_TOOLSET_NAME,
    )
