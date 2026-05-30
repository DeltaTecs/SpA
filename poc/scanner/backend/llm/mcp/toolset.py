"""Object-based access to an MCP server's tools.

An :class:`McpToolset` represents one MCP server, addressed by URL. It connects
on demand, auto-discovers the server's tools via the MCP ``list_tools`` call,
and executes tool invocations. The orchestrator (:mod:`llm.client`) aggregates
the tools from one or more toolsets and exposes them to the LLM.

The module follows the project convention (see ``http_mcp_bridge.py``) of
wrapping the async-only MCP client SDK in ``asyncio.run()`` so callers get a
synchronous API. The actual network work lives in module-level coroutine
functions so tests can substitute them without a live MCP server.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..logging_config import log_payload
from ..provider.base import ToolSpec

logger = logging.getLogger(__name__)

#: Transports understood by :class:`McpToolset`.
SUPPORTED_TRANSPORTS = ("streamable-http", "sse")


def _redact_url(url: str) -> str:
    """Return ``url`` with any query-parameter values masked for safe logging.

    Some MCP endpoints carry credentials in the query string (e.g. Tavily's
    ``?tavilyApiKey=...``). The unredacted URL is still used to connect to the
    remote server; only its logged representation is masked so secrets never
    reach the log file.
    """

    try:
        parts = urlparse(url)
    except ValueError:  # pragma: no cover - urlparse is very permissive
        return url
    if not parts.query:
        return url
    redacted = urlencode(
        [(key, "***") for key, _ in parse_qsl(parts.query, keep_blank_values=True)],
        safe="*",
    )
    return urlunparse(parts._replace(query=redacted))


def _to_jsonable(value: Any) -> Any:
    """Convert MCP SDK pydantic results into plain JSON-able structures.

    Mirrors the helper used by ``poc/mcp/hexstrike/http_mcp_bridge.py``.
    """

    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    if isinstance(value, dict):
        return {key: _to_jsonable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_to_jsonable(item) for item in value]
    return value


@asynccontextmanager
async def _mcp_session(url: str, transport: str):
    """Open an initialised MCP ``ClientSession`` for the given URL/transport."""

    from mcp import ClientSession

    if transport == "streamable-http":
        from mcp.client.streamable_http import streamablehttp_client

        async with streamablehttp_client(url) as streams:
            # streamablehttp_client yields (read, write, get_session_id).
            read_stream, write_stream = streams[0], streams[1]
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                yield session
    elif transport == "sse":
        from mcp.client.sse import sse_client

        async with sse_client(url) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                yield session
    else:  # pragma: no cover - guarded by McpToolset.__init__
        raise ValueError(f"Unsupported MCP transport: {transport}")


async def _list_tools_async(url: str, transport: str) -> dict[str, Any]:
    """Connect and return the server's ``list_tools`` result as a dict."""

    async with _mcp_session(url, transport) as session:
        return _to_jsonable(await session.list_tools())


async def _call_tool_async(
    url: str,
    transport: str,
    name: str,
    arguments: dict[str, Any],
    timeout: float,
) -> dict[str, Any]:
    """Connect and invoke a single tool, returning its result as a dict."""

    async with _mcp_session(url, transport) as session:
        result = await session.call_tool(
            name,
            arguments,
            read_timeout_seconds=timedelta(seconds=timeout),
        )
        return _to_jsonable(result)


class McpToolset:
    """A connection to a single MCP server, exposing its tools."""

    def __init__(
        self,
        url: str,
        *,
        name: str | None = None,
        transport: str = "streamable-http",
        timeout: float = 60.0,
    ) -> None:
        if transport not in SUPPORTED_TRANSPORTS:
            raise ValueError(
                f"Unsupported transport '{transport}'. "
                f"Supported: {', '.join(SUPPORTED_TRANSPORTS)}."
            )
        self.url = url
        self.transport = transport
        self.timeout = timeout
        # A short label for logs; defaults to the URL host.
        self.name = name or urlparse(url).netloc or url
        # URL with any query-string credentials masked, for use in logs.
        self._log_url = _redact_url(url)
        self._tool_specs: list[ToolSpec] | None = None
        logger.info(
            "Configured MCP toolset '%s' -> %s (%s)", self.name, self._log_url, self.transport
        )

    def list_tool_specs(self, *, refresh: bool = False) -> list[ToolSpec]:
        """Discover (and cache) the server's tools as :class:`ToolSpec` objects."""

        if self._tool_specs is not None and not refresh:
            return self._tool_specs

        logger.info("Discovering tools from MCP toolset '%s' (%s)", self.name, self._log_url)
        raw = asyncio.run(_list_tools_async(self.url, self.transport))
        tools = raw.get("tools", []) if isinstance(raw, dict) else []

        specs = [
            ToolSpec(
                name=tool.get("name", ""),
                description=tool.get("description") or "",
                parameters=tool.get("inputSchema") or {"type": "object", "properties": {}},
            )
            for tool in tools
            if tool.get("name")
        ]
        self._tool_specs = specs
        logger.info(
            "Toolset '%s' exposes %d tool(s): %s",
            self.name,
            len(specs),
            [spec.name for spec in specs],
        )
        return specs

    def call_tool(self, name: str, arguments: dict[str, Any]) -> str:
        """Invoke a tool by name and return its output flattened to text."""

        logger.info("Calling MCP tool '%s' on toolset '%s'", name, self.name)
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("MCP tool input name=%s arguments=%s", name, log_payload(arguments))

        try:
            raw = asyncio.run(
                _call_tool_async(self.url, self.transport, name, arguments, self.timeout)
            )
        except Exception:
            logger.exception("MCP tool '%s' failed on toolset '%s'", name, self.name)
            raise

        text = self._flatten_result(raw)
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("MCP tool output name=%s output=%s", name, log_payload(text))
        return text

    @staticmethod
    def _flatten_result(raw: Any) -> str:
        """Reduce an MCP call result to a single text string for the LLM.

        Concatenates the ``text`` of any text content blocks; falls back to a
        JSON dump of the whole payload when no text blocks are present.
        """

        if isinstance(raw, dict):
            content = raw.get("content")
            if isinstance(content, list):
                texts = [
                    block.get("text", "")
                    for block in content
                    if isinstance(block, dict) and block.get("type") == "text"
                ]
                if texts:
                    return "\n".join(text for text in texts if text)
        return log_payload(raw, max_chars=1_000_000)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"McpToolset(name={self.name!r}, url={self._log_url!r}, "
            f"transport={self.transport!r})"
        )
