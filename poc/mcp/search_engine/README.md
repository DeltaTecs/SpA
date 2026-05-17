# Search Engine MCP Service

This service exposes Tavily's stdio MCP server over the same streamable HTTP
transport used by the rest of the stack.

The container preinstalls `supergateway` and `tavily-mcp` at build time. At
runtime, `search-engine-entrypoint` starts Tavily as the stdio child process and
publishes `/mcp` on port `8768`.

Required environment:

- `TAVILY_API_KEY`

Optional environment:

- `TAVILY_HUMAN_ID`
- `TAVILY_DEFAULT_PARAMETERS`, forwarded as Tavily's `DEFAULT_PARAMETERS`
- `SEARCH_MCP_PORT`, default `8768`
- `SEARCH_MCP_PATH`, default `/mcp`
- `SEARCH_MCP_LOG_LEVEL`, default `info`
