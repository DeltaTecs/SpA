# Packet DB MCP Server

MCP server that provides read-only access to packet metadata and decrypted payloads stored in the PoC PostgreSQL database.

## Tools

- `packet_info(packet_id: int)`
  - Basic flow info (src/dst IP + ports, transport protocol)
  - Protocol layers (resolved from `protocol_ids`)
  - Application protocol guess (`http`, `websocket`, `unknown`)
  - If HTTP header(s) are associated, includes the `text_header` fields
  - If cleartext payload exists, includes a **preview** hexdump of the first 256 bytes (hex + ASCII)

- `packet_payload_hexdump(packet_id: int)`
  - Returns the **full** cleartext payload as hexdump (hex + ASCII)

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
