# Packet DB MCP Server

MCP server that provides packet metadata/payload lookup tools and event persistence tools for the PoC PostgreSQL database.

## Tools

- `packet_info(packet_id: int)`
  - Basic flow info (src/dst IP + ports, transport protocol)
  - Packet ID, packet number, recording ID, conversation ID
  - Absolute timestamp and offset from the first packet in the recording
  - Direction (`inbound`, `outbound`, or `unknown`) and raw `from_local`
  - Protocol layers (resolved from `protocol_ids`)
  - Entropy, clear payload length, TCP payload length, and UDP length when present
  - Application protocol guess (`http`, `websocket`, `unknown`)
  - If HTTP header(s) are associated, includes stream/version metadata and the `text_header` fields
  - If cleartext payload exists, includes a **preview** hexdump of the first 256 bytes (hex + ASCII)

- `packet_payload_hexdump(packet_id: int)`
  - Returns the **full** cleartext payload as hexdump (hex + ASCII)

- `conversation_packets(conversation_id: int, packet_id: int = 0, before: int = 5, after: int = 5)`
  - Returns rich `packet_info` output for packets in one conversation
  - If `packet_id` is provided, returns a conversation-local window around that packet
  - Helps avoid unrelated interleaved packets from other flows

- `packets_in_time_window(recording_id: int, start_ms: int, end_ms: int, max_packets: int = 40)`
  - Returns rich `packet_info` output for packets in a time window
  - `start_ms` and `end_ms` are recording-relative offsets; epoch millisecond values are also accepted

- `create_event_and_assign_packet(packet_id: int, description: str)`
  - Atomically creates a new event and assigns the packet to it
  - Intended for orchestrators after validating an LLM decision

## Configuration

The server uses the same environment variables as the rest of the PoC:

- `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`

Optionally you can set `DB_DSN` (psycopg2 DSN string) instead.

Transport:

- `MCP_TRANSPORT` = `sse` (default) or `stdio`
- `MCP_HOST` (default `0.0.0.0`)
- `MCP_PORT` (default `8765`)

## Running with docker-compose

This repo’s main compose file is in `poc/docker-compose.yml`.

After the compose service is added, run:

- `docker compose up -d mcp-packet-db`

The MCP server will listen on `http://localhost:8765` (SSE transport).

## Quick test script (prints tool outputs)

For a given `packet_id`, this prints the output of `packet_info` and optionally `packet_payload_hexdump`.

- Local (uses your current Python):
  - `python poc/mcp/packet_db_server/scripts/test_packet.py 123 --full-payload`

- From the running container:
  - `docker exec -it mcp-packet-db python /app/src/packet_db_server/server.py` (runs server)
  - Or run the script in a one-off container:
    - `docker compose run --rm mcp-packet-db python /app/scripts/test_packet.py 123 --full-payload`
