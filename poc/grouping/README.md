# Packet Event Assignment Module

This module connects to the packet-db MCP server, iterates over one recording,
and lets the LLM assign payload-bearing packets to application-level events.

The LLM can query tuple-compatible existing events, assign the current packet,
or create a new event and assign the packet atomically. Empty clear application
payload packets are skipped.

## Flow

1. Connect to the MCP packet-db server.
2. Load packet IDs for the selected recording.
3. Fetch `packet_info` for each packet in capture order.
4. Skip packets whose clear application payload is empty.
5. Ask the LLM to inspect matching events through MCP.
6. Assign the packet to a matching event or create a new event.

The MCP server filters existing events by normalized IP/port tuple before the
LLM sees them, and assignment rejects tuple mismatches server-side.

If `SEARCH_MCP_URL` or `SEARCH_MCP_SERVERS` is configured, grouping also exposes
only the Tavily `tavily_search` and `tavily_extract` MCP tools with names such
as `search_engine__tavily_search`. If neither search variable is set and
`TAVILY_API_KEY` is present, grouping connects to Tavily's official remote MCP
endpoint at `https://mcp.tavily.com/mcp/`. Tavily crawl/map/research tools are
intentionally hidden from grouping so the LLM sees only packet database tools
plus the approved public web search/extract tools.

## Usage

From the `poc` directory:

```bash
./run_grouping.sh <recording_id> [model_name]
```

PowerShell:

```powershell
.\run_grouping.ps1 -RecordingId <recording_id> [-Model <model_name>]
```

Examples:

```bash
./run_grouping.sh 1
./run_grouping.sh 2 qwen3:8b
./run_grouping.sh 1 --provider deepseek --api-key YOUR_DEEPSEEK_API_KEY
```
