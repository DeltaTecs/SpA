# Vulnerability Scanner

Web and backend services for event-based vulnerability-assessment workflows.

## Layout

- `backend/llm` contains the phase-one LLM scanner implementation.
- `backend/api` exposes HTTP endpoints that import and call `backend/llm` functions.
- `frontend` serves the browser UI and proxies `/api/*` to `scanner-api`.

Phase two remains a placeholder and returns HTTP 501.

## Docker Compose

From `poc`:

```bash
docker compose up -d
```

Open the frontend at:

```text
http://localhost:8091
```

The API is also exposed directly at:

```text
http://localhost:8090
```

The frontend provider dropdown is populated by `/api/config`. Ollama is always
available; DeepSeek, OpenAI, and Gemini appear when their server-side API key
environment variables are configured. Optional comma-separated model lists can
be set with `SCANNER_OLLAMA_MODELS`, `SCANNER_DEEPSEEK_MODELS`,
`SCANNER_OPENAI_MODELS`, and `SCANNER_GEMINI_MODELS`; otherwise the UI uses
the built-in defaults for each provider.

Evaluations are persisted in the PostgreSQL `"PreScan"` table, keyed one-to-one
by `event_id`. Re-evaluating an event replaces that event's stored pre-scan.

## Running Scans

Run scans from the browser UI or through the HTTP API exposed by
`scanner-api`.
