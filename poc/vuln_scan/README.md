# Vulnerability Scanner

Web and backend services for event-based vulnerability-assessment workflows.

## Layout

- `backend/llm` contains shared scanner orchestration, phase-one summaries,
  phase-two vulnerability analysis, and MCP client/proxy code.
- `backend/api` exposes HTTP endpoints that import and call `backend/llm` functions.
- `frontend` serves the browser UI and proxies `/api/*` to `scanner-api`.

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

Phase-one evaluations are persisted in the PostgreSQL `pre_scan` table, keyed
one-to-one by `event_id`. Re-evaluating an event replaces that event's stored
pre-scan.

Phase-two vulnerability analysis is started from the UI under
`Evaluation -> Vulnerability Analysis`. Each run is held in API memory while it
is active. The UI polls for progress, shows pending MCP tool calls in full, and
requires an approve/deny decision before the proxy executes the call.

The default phase-two MCP exposure is configured with:

```text
PHASE2_MCP_SERVERS=packet=http://mcp-packet-db:8765,hexstrike=http://mcp-hexstrike:8767,bash=http://mcp-hexstrike:8766
PHASE2_MCP_TOOL_TIMEOUT_SECONDS=900
PHASE2_APPROVAL_TIMEOUT_SECONDS=3600
```

For safety while this flow is being validated, all scanner prompts end with:

```text
THIS IS A TEST. DO NOT RUN ANY TOOLS OR ANY ANALYSIS ON ANYTHING. JUST REPLY 'TEST COMPLETE'.
```

## Running Scans

Run scans from the browser UI or through the HTTP API exposed by
`scanner-api`.
