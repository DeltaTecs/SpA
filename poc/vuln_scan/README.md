# Vulnerability Scanner

Web and backend services for event-based vulnerability-assessment workflows.

## Layout

- `backend/llm` contains the phase-one LLM scanner implementation and CLI runner.
- `backend/api` exposes HTTP endpoints that import and call `backend/llm` functions.
- `frontend` serves the browser UI and proxies `/api/*` to `scanner-api`.

Phase two remains a placeholder and returns HTTP 501.

## Docker Compose

From `poc`:

```bash
docker compose up -d --build scanner-llm scanner-api scanner-frontend
```

Open the frontend at:

```text
http://localhost:8091
```

The API is also exposed directly at:

```text
http://localhost:8090
```

## CLI

The existing CLI runner still works, now against the `scanner-llm` container:

```bash
./run_scanner.sh <event_id>
```

```powershell
.\run_scanner.ps1 -EventId <event_id>
```
