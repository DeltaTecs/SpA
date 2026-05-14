# Vulnerability Scanner

Vulnerability assessment triage for authorized targets. Phase one loads a
database event, gives an LLM read-only access to selected packet MCP tools, and
emits a summary. Phase two reuses the same analyzer, event context, and MCP
client foundations, then exposes configured MCP servers through a permission
proxy.

## MCP Tools Exposed To The LLM

- `packet_info(packet_id)`
- `packet_payload_hexdump(packet_id)`
- `conversation_packets(conversation_id, packet_id, before, after)`
- `packets_in_time_window(recording_id, start_ms, end_ms, max_packets)`

The scanner orchestrator also uses `event_packets(event_id)` to resolve the
packets assigned to the requested event before invoking the LLM.

Phase-two tools are discovered from `PHASE2_MCP_SERVERS` and exposed with
server-prefixed names such as `packet__packet_info`, `hexstrike__nmap_scan`,
and `bash__bash`. Every phase-two tool call blocks on the API/UI approval
callback before the underlying MCP call runs.

All prompts currently end with the test directive that instructs the model to
reply `TEST COMPLETE` without running tools or analysis.

## Usage

Run scans through the web/API service, or invoke the scanner directly inside
the `scanner-llm` container:

```bash
python3 /app/src/scanner.py \
    --event-id 7 \
    --mcp-url http://mcp-packet-db:8765 \
    --provider deepseek \
    --api-key YOUR_KEY
```

## Output

The phase-one summary is printed as Markdown and can optionally be written to a
container path with `--output` or the `OUTPUT` environment variable.
