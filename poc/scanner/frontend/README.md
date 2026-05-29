# Scanner Frontend

Web UI for the traffic-analysis tool. It inspects recorded traffic for a
recording and presents AI-powered analysis surfaces. Three areas:

- **Dashboard** — packet count and statistics for a recording (default id `1`):
  protocol distribution, incoming/outgoing split, payload-entropy histogram, top
  remote IPs, and a remote-IP → host → path endpoint tree.
- **Packet Explorer** — a paginated list of packets with click-through detail
  (headers + payload hexdump/text). A toggle tints rows by association
  (normalized 5-tuple, split per HTTP stream) so related packets share a color.
  Filters narrow by decrypted payload, HTTP header text, and application
  protocol bucket.
- **Attack** — a **Create Plan** tab that configures and launches LLM-driven
  vulnerability-scan planning (plus an Overview placeholder for upcoming active
  scans). Create Plan compiles a recording's *interesting data exchanges*
  (non-HTTP conversation flows + deduplicated HTTP request/response pairs), lets
  you inspect/edit/deselect them, pick an LLM provider + model + analysis task,
  then runs one concurrent LLM session per exchange and annotates each with the
  suggested vulnerability checks.

## Architecture

```
browser ── frontend server (FastAPI, :8093) ─┬─ /api/*       ─► db-api (:8092) ── postgres
              │ serves the built React SPA    └─ /api/plan/*  ─► scanner-backend (:8094)
              └ logs ─► poc/logs/scanner-frontend.log
```

The frontend holds **no database logic**; packet data comes from the db-api
(`/packets`, `/recordings`, `/stats/{id}`, `/recordings/{id}/exchanges`) and LLM
planning from the scanner-backend (`/plan/providers`, `/plan/tasks`,
`/plan/jobs`). Keeping the SPA same-origin (it calls `/api/*`) avoids any CORS
dependency; the server proxies the more-specific `/api/plan/*` to the backend and
everything else to the db-api.

```
server/            FastAPI app: serves SPA, proxies /api/*, logging
  app/
    main.py        app wiring, request logging, SPA fallback, two proxy mounts
    proxy.py       httpx passthrough (parameterized by upstream client)
    config.py      DB_API_URL, BACKEND_URL, static dir, timeout
    logging_config.py
web/               React + TypeScript + Vite SPA
  src/
    api/           typed client (mirrors db-api + scanner-backend schemas)
    pages/         Dashboard, Explorer, Attack
    components/    dashboard/, explorer/, attack/, common/
    lib/           colors, formatting, hexdump, useFetch, usePolling
Dockerfile         multi-stage: build SPA -> serve from python
```

The Create Plan UI renders each analysis task's result through a small renderer
registry (`components/attack/results/resultRenderers.tsx`), so a new backend task
type only needs its own renderer entry.

## Run with docker-compose (recommended)

From `poc/`:

```bash
docker compose up -d --build db db-api mcp-packet-db scanner-backend frontend
```

Open <http://localhost:8093>. The dashboard reads recording `1` by default. The
Attack → Create Plan tab needs `scanner-backend` (and `mcp-packet-db` for the LLM
to read packets); set provider API keys in `.env` (see `poc/.env.sample`). Logs
are written to `poc/logs/scanner-frontend.log`, `poc/logs/db-api.log` and
`poc/logs/scanner-llm.log`.

## Local development

Run the db-api (and database) via compose, then run the server and SPA locally:

```bash
# 1. database + API
docker compose up -d db db-api          # db-api on http://localhost:8092

# 2. frontend server (proxies to the db-api)
cd scanner/frontend/server
pip install -r requirements.txt
DB_API_URL=http://localhost:8092 uvicorn app.main:app --reload --port 8000

# 3. SPA dev server (proxies /api -> http://localhost:8000)
cd ../web
npm install
npm run dev                              # http://localhost:5173
```

To skip running the python server during pure-UI work, point the Vite proxy
target in `web/vite.config.ts` at the db-api (`http://localhost:8092`) and add a
`rewrite` that strips the `/api` prefix.

## Configuration

| Env var               | Default                 | Purpose                                   |
| --------------------- | ----------------------- | ----------------------------------------- |
| `DB_API_URL`          | `http://db-api:8000`    | Upstream packet database API.             |
| `BACKEND_URL`         | `http://scanner-backend:8000` | Upstream LLM scan-planning backend (`/api/plan/*`). |
| `FRONTEND_STATIC_DIR` | `app/static`            | Built SPA location served by the server.  |
| `FRONTEND_LOG_DIR`    | `poc/logs`              | Log directory (set to `/app/logs` in Docker). |
| `LOG_LEVEL`           | `INFO`                  | `VERBOSE`/`DEBUG` for verbose logging.    |
| `PROXY_TIMEOUT`       | `30`                    | Upstream request timeout (seconds).       |

## Extending

- New data needs → add an endpoint to the db-api (`poc/db/api/app/...`); the
  proxy forwards it automatically. Add a typed call in `web/src/api/`.
- New page → add under `web/src/pages/`, a route in `App.tsx`, and a nav item in
  `layout/Sidebar.tsx`.
- Attack / LLM features → build UI under `web/src/components/attack/`; server-side
  LLM orchestration lives in the `scanner-backend` service (`poc/scanner/backend`),
  reached via the `/api/plan/*` proxy. A new analysis task type is added there
  (see its README) plus a renderer in `components/attack/results/`.
