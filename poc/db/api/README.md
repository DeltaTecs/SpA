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

Each domain (currently `packets`) keeps its repository, router, and schemas
together, so new areas of the database get their own sibling package.

## Endpoints

| Method | Path                          | Description                                   |
| ------ | ----------------------------- | --------------------------------------------- |
| GET    | `/health`                     | Liveness probe.                               |
| GET    | `/packets`                    | List packets (filterable + paginated).        |
| GET    | `/packets/{packet_id}`        | One packet with parsed protocol headers.      |
| GET    | `/packets/{packet_id}/payload`| Raw packet bytes, base64-encoded.             |

### `GET /packets` query parameters

- `recording_id` — limit to one recording
- `conversation_id` — limit to one conversation
- `from_local` — `true`/`false` traffic direction
- `protocol` — protocol name that must appear in the stack (e.g. `TCP`, `HTTP`)
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
