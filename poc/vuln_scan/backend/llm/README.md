# Vulnerability Scanner

Phase-one vulnerability assessment triage for authorized targets. The scanner
loads a database event, gives an LLM read-only access to selected packet MCP
tools, and emits a summary for later manual or automated phase-two work.

Phase two is intentionally not implemented yet.

## MCP Tools Exposed To The LLM

- `packet_info(packet_id)`
- `packet_payload_hexdump(packet_id)`
- `conversation_packets(conversation_id, packet_id, before, after)`
- `packets_in_time_window(recording_id, start_ms, end_ms, max_packets)`

The scanner orchestrator also uses `event_packets(event_id)` to resolve the
packets assigned to the requested event before invoking the LLM.

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
