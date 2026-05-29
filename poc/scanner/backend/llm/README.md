# LLM / MCP client

A self-contained module that runs a prompt against one or more **MCP server
toolsets** using a configurable **LLM provider**, executing the agentic loop
(LLM → tool call → tool result → LLM → … → final answer).

## Layout

```
llm/
├── client.py            # McpLlmClient — the orchestrator (agentic loop)
├── logging_config.py    # configure_logging() -> rotating file in poc/logs
├── provider/            # LLM providers + factory
│   ├── base.py          # BaseProvider (ABC) + ChatMessage/ToolSpec/ToolCall/ChatResult
│   ├── openai_compatible.py  # shared impl on the official `openai` SDK
│   ├── openai_provider.py    # OpenAIProvider
│   ├── deepseek_provider.py  # DeepSeekProvider
│   ├── local_provider.py     # LocalProvider (Qwen / Ollama / LM Studio; no key)
│   └── factory.py            # ProviderFactory.create(type, api_key, ...)
├── mcp/
│   └── toolset.py       # McpToolset — connect to an MCP URL, discover & call tools
└── tests/               # stdlib unittest suite (no network required)
```

## Design

* **Synchronous** API. The MCP Python SDK is async-only, so MCP calls are wrapped
  in `asyncio.run()` internally (mirroring `poc/mcp/hexstrike/http_mcp_bridge.py`).
* **Factory pattern** for providers. `ProviderFactory.create()` is handed the API
  key and forwards it to the provider. OpenAI and DeepSeek require a key; the
  local provider does not.
* **OpenAI-compatible** providers share one implementation
  (`OpenAICompatibleProvider`) built on the official `openai` SDK; DeepSeek and the
  local server differ only by `base_url`/`model`.
* **Object-based MCP toolsets.** `McpToolset(url)` connects to an MCP server and
  auto-discovers its tools via `list_tools()` — no manual tool description needed.

## Usage

```python
import os
from llm import ProviderFactory, McpToolset, McpLlmClient, configure_logging

configure_logging()  # writes to poc/logs/scanner-llm.log

# Pick a provider via the factory (the factory receives the API key):
provider = ProviderFactory.create("deepseek", api_key=os.environ["DEEPSEEK_API_KEY"])
# provider = ProviderFactory.create("openai", api_key=os.environ["OPENAI_API_KEY"])
# provider = ProviderFactory.create("local")  # Qwen via local server, no key

# Point at one or more MCP servers (the packet-db server runs streamable-http):
toolset = McpToolset("http://localhost:8765/mcp")

client = McpLlmClient(provider, [toolset])
result = client.run("List the packet IDs for recording 1, then summarise them.")
print(result.output)
```

## Configuration (environment)

| Variable | Purpose | Default |
| --- | --- | --- |
| `LOG_LEVEL` | `INFO` / `DEBUG` / `VERBOSE` (VERBOSE→DEBUG) | `INFO` |
| `LLM_LOG_DIR` | Override the log directory | `poc/logs` |
| `LLM_LOG_MAX_CHARS` | Truncation limit for DEBUG payload logging | `20000` |
| `LOCAL_LLM_BASE_URL` | Local provider endpoint | `http://localhost:11434/v1` |
| `LOCAL_LLM_MODEL` | Local provider model | `qwen2.5` |

API keys are passed explicitly to `ProviderFactory.create(...)`; the module does
not read provider keys from the environment itself.

## Tests

```bash
python -m unittest discover -s poc/scanner/backend/llm/tests -v
```

The suite uses fakes/mocks throughout, so it needs neither network access, a real
API key, nor a running MCP server.
```
