#!/bin/sh
set -eu

SEARCH_MCP_PORT="${SEARCH_MCP_PORT:-8768}"
SEARCH_MCP_PATH="${SEARCH_MCP_PATH:-/mcp}"
SEARCH_MCP_LOG_LEVEL="${SEARCH_MCP_LOG_LEVEL:-info}"

if [ -n "${TAVILY_DEFAULT_PARAMETERS:-}" ] && [ -z "${DEFAULT_PARAMETERS:-}" ]; then
  export DEFAULT_PARAMETERS="${TAVILY_DEFAULT_PARAMETERS}"
fi

if [ -z "${TAVILY_API_KEY:-}" ]; then
  echo "TAVILY_API_KEY is not set; Tavily MCP tool calls will fail until it is configured." >&2
fi

# Tavily's MCP package speaks stdio. Supergateway is the narrow transport bridge
# that exposes it as streamable HTTP for the Python MCP clients in this repo.
exec supergateway \
  --stdio "tavily-mcp" \
  --outputTransport streamableHttp \
  --stateful \
  --port "${SEARCH_MCP_PORT}" \
  --streamableHttpPath "${SEARCH_MCP_PATH}" \
  --logLevel "${SEARCH_MCP_LOG_LEVEL}" \
  "$@"
