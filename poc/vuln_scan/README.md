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

The UI includes Browse buttons for user actions and the application
description. Selected text files are read in the browser and sent with the scan
request. If no file is selected, the backend uses its configured `USER_INTEND`
and `APP_DETAILS` defaults.

Phase-two vulnerability analysis is started from the UI under
`Evaluation -> Vulnerability Analysis`. Each run is held in API memory while it
is active. The UI polls for progress, shows pending MCP tool calls in full, and
requires an approve/deny decision before the proxy executes the call.

The **Configure approval** button on the Vulnerability Analysis tab selects how
MCP tool calls are approved:

- **Manual approval** - every tool call waits for a decision (the default).
- **Auto approve database tools** - packet-database queries run without
  prompting; other tools stay manual.
- **Auto approve all tools** - every tool call runs without prompting.
- **Smart approve non-db tools** - a dedicated LLM reviewer auto-approves a
  non-database tool call only when it satisfies the user constraints, poses no
  risk to the local machine, and does not exploit the remote target beyond what
  is needed to prove a vulnerability. Database tools are auto-approved. By
  default a call the reviewer rejects is escalated to manual approval, with the
  reviewer's reasoning shown on the approval card; this escalation can be turned
  off in the menu, in which case the rejection is final. The reviewer's LLM
  provider and model are chosen in the same menu, independent of the analysis
  LLM.

Whenever a tool call is denied - by the smart reviewer, by a timeout, or by the
user - the denial reason is returned to the analysis LLM as the tool result so
it can adjust the call and try again. The manual approval card includes an
optional free-text field for the user to add a denial reason.

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
