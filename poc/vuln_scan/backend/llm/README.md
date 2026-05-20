# Vulnerability Scanner

Vulnerability assessment triage for authorized targets. Phase one loads a
database event, gives an LLM read-only access to selected packet MCP tools, and
emits a summary. If web search is enabled for a run and `SEARCH_MCP_URL` or
`SEARCH_MCP_SERVERS` is configured, phase one also exposes approved
search-engine MCP tools as read-only context tools. Phase two reuses the same
analyzer, event context, and MCP client foundations, then exposes configured MCP
servers through a permission proxy.

## MCP Tools Exposed To The LLM

- `packet_info(packet_id)`
- `packet_payload_hexdump(packet_id)`
- `conversation_packets(conversation_id, packet_id, before, after)`
- `packets_in_time_window(recording_id, start_ms, end_ms, max_packets)`

The scanner orchestrator also uses `event_packets(event_id)` to resolve the
packets assigned to the requested event before invoking the LLM.

Search tools are discovered from `SEARCH_MCP_URL` or `SEARCH_MCP_SERVERS`. If
neither is set and `TAVILY_API_KEY` is present, the scanner uses Tavily's
official remote MCP endpoint at `https://mcp.tavily.com/mcp/`. Search tools use
server-prefixed names such as `search_engine__tavily_search`. Tavily tools are
limited project-wide to `tavily_search` and `tavily_extract`.

Phase-two tools are discovered from `PHASE2_MCP_SERVERS` and exposed with
server-prefixed names such as `packet__conversation_packets`,
`search_engine__tavily_search`, `hexstrike__nmap_scan`, and `bash__bash`.
HexStrike tools are filtered by the selected analysis tracks' allowlists.
Packet DB, search-engine, and Bash tools are otherwise still exposed normally,
except the packet DB tools `packet_info`,
`packet_payload_hexdump`, `packets_in_time_window`, and `event_packets` are not
exposed in phase two. Every phase-two tool call blocks on the API/UI approval
callback before the underlying MCP call runs.

Set `TAVILY_API_KEY` in `poc/.env` before using the Tavily remote MCP tools.

All prompts currently end with the test directive that instructs the model to
reply `TEST COMPLETE` without running tools or analysis.

## Usage

Run phase-one summaries and phase-two analysis through the web/API service.
The standalone command-line scanner entry point has been removed so scan runs
are coordinated through the API and UI.

## Output

The phase-one summary is returned as Markdown from the API and stored for reuse
by phase two.
