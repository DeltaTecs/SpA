# Scanner Backend

HTTP service that exposes LLM-driven scan **planning** to the frontend's
"Create Plan" tab. It wraps the standalone [`llm`](llm/) package (providers +
MCP toolsets + agentic loop) and runs one LLM session per data exchange,
concurrently, returning suggested vulnerability checks.

It runs as the `scanner-backend` service in the parent `docker-compose.yml`
(host port `8094`, container `8000`) and is reached by the frontend server's
`/api/plan/*` proxy. It holds **no database logic**: packet detail reaches the
model through the `mcp-packet-db` MCP server and web search through Tavily's
remote MCP server.

## Layout

```
app/
  main.py            # FastAPI app, /health, /providers, /tasks, /jobs
  config.py          # Settings from the environment (singleton `settings`)
  schemas.py         # Pydantic request/response models
  providers.py       # provider + model catalogue for the config UI
  tasks/             # the extension surface — analysis task types
    base.py          # AnalysisTask contract + default toolset assembly
    registry.py      # name -> task registry (@register / get / available)
    vulnerability_checks.py   # the first task type
  jobs/
    store.py         # thread-safe, in-memory job store (task-agnostic)
    runner.py        # bounded ThreadPoolExecutor; task-agnostic worker body
llm/                 # bundled standalone LLM/MCP package (see llm/README.md)
```

## Endpoints

| Method | Path             | Description                                         |
| ------ | ---------------- | --------------------------------------------------- |
| GET    | `/health`        | Liveness probe.                                     |
| GET    | `/providers`     | Selectable LLM providers and their model options.   |
| GET    | `/tasks`         | Registered analysis task types (UI task picker).    |
| POST   | `/jobs`          | Start a job over posted exchanges. Returns `job_id`.|
| GET    | `/jobs/{job_id}` | Job status + per-exchange results (poll until done).|

The frontend reaches these under `/api/plan/*` (the frontend server strips the
`/plan` prefix and forwards the rest here).

## Adding a new analysis task type

1. Add a module under `app/tasks/` with a class extending `AnalysisTask`
   (define `task_type`, prompts, optional `select_toolsets`, and `parse_output`
   returning a versioned `TaskResult`).
2. Decorate it with `@register` and import the module from `app/tasks/__init__.py`.

Nothing else changes: `/tasks`, the job runner, the store and the transport are
task-agnostic, and the frontend renders the result via its renderer registry.

## Configuration (environment)

| Variable | Purpose | Default |
| -------- | ------- | ------- |
| `MCP_PACKET_DB_URL` | packet-db MCP endpoint | `http://mcp-packet-db:8765/mcp` |
| `HEXSTRIKE_BASH_MCP_URL` | optional HexStrike bash MCP endpoint | _(unset -> disabled)_ |
| `HEXSTRIKE_TOOLS_MCP_URL` | optional HexStrike tools MCP endpoint | _(unset -> disabled)_ |
| `HEXSTRIKE_TOOLS_ADMIN_TOKEN` | required shared secret when HexStrike tools are enabled | _(unset)_ |
| `TAVILY_API_KEY` | enables the Tavily web-search MCP toolset | _(unset → disabled)_ |
| `OPENAI_API_KEY` / `DEEPSEEK_API_KEY` | keys for the keyed providers | _(unset)_ |
| `PLAN_MAX_CONCURRENCY` | worker threads (concurrent sessions) | `4` |
| `PLAN_MAX_ITERATIONS` | default agentic-loop cap | `10` |
| `PLAN_MCP_TIMEOUT` / `PLAN_LLM_TIMEOUT` | per-call timeouts (seconds) | `60` / `120` |
| `LOG_LEVEL`, `LLM_LOG_DIR` | logging (shared with the `llm` package) | `INFO`, `poc/logs` |

Jobs are stored in memory and do not survive a restart (PoC).

## Tests

```
python -m unittest discover -s tests
```

Unit tests use a stub provider and a fake task (no network/MCP).
