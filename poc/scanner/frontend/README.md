# Scanner Frontend

Web UI for the traffic-analysis tool. It inspects recorded traffic for a
recording and presents AI-powered analysis surfaces. Three areas:

- **Dashboard** — packet count and statistics for a recording (default id `1`):
  protocol distribution, incoming/outgoing split, payload-entropy histogram, top
  remote IPs, and a remote-IP → host → path endpoint tree.
- **Packet Explorer** — a paginated list of packets with click-through detail
  (headers + payload hexdump/text). A toggle tints rows by association
  (conversation, split per HTTP stream) so related packets share a color.
- **Attack** — placeholder for upcoming AI-powered scans.

## Architecture

```
browser ── frontend server (FastAPI, :8093) ── db-api (:8092) ── postgres
              │ serves the built React SPA
              │ proxies /api/* ─────────────► db-api endpoints
              └ logs ─► poc/logs/scanner-frontend.log
```

The frontend holds **no database logic**; all data comes from the db-api
(`/packets`, `/recordings`, `/stats/{id}`). Keeping the SPA same-origin (it calls
`/api/*`, proxied to the db-api) avoids any CORS dependency and gives one place
to add the future attack-orchestration endpoints.

```
server/            FastAPI app: serves SPA, proxies /api/*, logging
  app/
    main.py        app wiring, request logging, SPA fallback
    proxy.py       httpx passthrough to db-api
    config.py      DB_API_URL, static dir, timeout
    logging_config.py
web/               React + TypeScript + Vite SPA
  src/
    api/           typed client (mirrors db-api schemas)
    pages/         Dashboard, Explorer, Attack
    components/    dashboard/, explorer/, common/
    lib/           colors, formatting, hexdump, useFetch
Dockerfile         multi-stage: build SPA -> serve from python
```

## Run with docker-compose (recommended)

From `poc/`:

```bash
docker compose up -d --build db db-api frontend
```

Open <http://localhost:8093>. The dashboard reads recording `1` by default.
Logs are written to `poc/logs/scanner-frontend.log` and `poc/logs/db-api.log`.

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
| `FRONTEND_STATIC_DIR` | `app/static`            | Built SPA location served by the server.  |
| `FRONTEND_LOG_DIR`    | `poc/logs`              | Log directory (set to `/app/logs` in Docker). |
| `LOG_LEVEL`           | `INFO`                  | `VERBOSE`/`DEBUG` for verbose logging.    |
| `PROXY_TIMEOUT`       | `30`                    | Upstream request timeout (seconds).       |

## Extending

- New data needs → add an endpoint to the db-api (`poc/db/api/app/...`); the
  proxy forwards it automatically. Add a typed call in `web/src/api/`.
- New page → add under `web/src/pages/`, a route in `App.tsx`, and a nav item in
  `layout/Sidebar.tsx`.
- Attack features → build under `web/src/components/attack/` and, for
  server-side orchestration, add routers to `server/app` (alongside the proxy).
