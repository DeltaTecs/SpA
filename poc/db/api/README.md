# Packet Database API

HTTP API for reading data from the packet database. It runs as the `db-api`
service in the parent `docker-compose.yml` and is reachable by other containers
over the dedicated `db-api-network` Docker network (and on host port `8092`).

## Layout

```
app/
  config.py            # DB settings from the environment
  db.py                # connection / cursor helpers (commit + rollback)
  main.py              # FastAPI app, CORS, /health, router wiring
  packets/
    repository.py      # SQL data access for the `packet` table
    router.py          # /packets HTTP endpoints
    schemas.py         # Pydantic request/response models
```

Each domain (`packets`, `stats`, `exchanges`) keeps its repository, router, and
schemas together, so new areas of the database get their own sibling package.
`http_parsing.py`, `flows.py` (normalized 5-tuple / association keys) and
`logging_config.py` are shared helpers.

## Endpoints

| Method | Path                          | Description                                   |
| ------ | ----------------------------- | --------------------------------------------- |
| GET    | `/health`                     | Liveness probe.                               |
| GET    | `/packets`                    | List packets (filterable + paginated, enriched with `remote_ip`, ports, an `http` summary and a normalized flow `association_key`). |
| GET    | `/packets/{packet_id}`        | One packet with parsed protocol headers.      |
| GET    | `/packets/{packet_id}/payload`| Raw packet bytes, base64-encoded.             |
| GET    | `/recordings`                 | All recordings with their packet counts.      |
| GET    | `/stats/{recording_id}`       | Aggregated stats: protocol/direction/entropy distributions, top remote IPs, and an IP→host→path endpoint tree. |
| GET    | `/recordings/{recording_id}/exchanges` | Interesting data exchanges: non-HTTP conversation flows (clear payload) and deduplicated HTTP request/response pairs. |

### `GET /packets` query parameters

- `recording_id` — limit to one recording
- `conversation_id` — limit to one conversation
- `from_local` — `true`/`false` traffic direction
- `protocol` — protocol name that must appear in the stack (e.g. `TCP`, `HTTP`)
- `has_clear_payload` — `true` for packets with decrypted application payload
- `has_http_header_text` — `true` for packets with non-empty stored HTTP header text
- `app_protocol` — application protocol bucket: `http`, `websocket`, or `other`
- `start_ms` / `end_ms` — epoch-millisecond timestamp bounds
- `limit` (default 100, max 1000) and `offset`

Interactive docs are served at `/docs` once the service is running.

## Configuration

Connection settings come from the environment (provided by `docker-compose.yml`):
`DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`, or a single `DB_DSN`.

## Run locally

```bash
# From poc/db/api, with the database reachable via the DB_* env vars
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```
