# Packet Grouping / Analysis Module

This module analyzes network packets using a local LLM (via Ollama) or a hosted LLM API and groups them into application-specific events.

## Overview

The packet analyzer uses LangChain with Ollama to:
1. Load packets from the database for a specific recording
2. Summarize conversations, HTTP streams, and recording-relative time windows
3. Use those summaries to create event candidates
4. Ask the LLM for a structured packet decision:
   `{packet_id, event_id | new_event, confidence, rationale}`
5. Validate the decision in the orchestrator and persist it to the database

The LLM only receives read-only MCP tools. It can request packet details,
conversation-local neighbors, conversation slices, and recording-relative time
windows around user actions. HTTP stream summaries are used only when the
database exposes enough `stream_id` metadata to connect multiple packets; HTTP
packets without a stream ID are still covered by conversation and time-window
summaries. The LLM cannot create events or assign packets directly. New event
creation and packet assignment are performed by the orchestrator after
validation. New event creation uses an atomic create-and-assign MCP operation so
a failed packet assignment does not leave a newly-created orphan event.

## Requirements

- Docker with NVIDIA GPU support
- Ollama (installed automatically in the container)
- PostgreSQL database with packets already imported

## Default Model

The default model is `qwen3:8b` (Qwen3 8B with reasoning/thinking mode, ~5.5GB).
This can be changed via the `--model` argument or environment variable.

## Usage

### From the poc directory (host machine):

```bash
# Bash/Linux/WSL
./run_grouping.sh <recording_id> [model_name]

# PowerShell/Windows
.\run_grouping.ps1 -RecordingId <recording_id> [-Model <model_name>]
```

### Examples:

```bash
# Analyze recording 1 with default model
./run_grouping.sh 1

# Analyze recording 2 with a specific Ollama model
./run_grouping.sh 2 qwen3:8b

# Analyze recording 1 with DeepSeek API
./run_grouping.sh 1 --provider deepseek --api-key YOUR_DEEPSEEK_API_KEY

# PowerShell / Windows
.\run_grouping.ps1 -RecordingId 1 -Provider deepseek -ApiKey YOUR_DEEPSEEK_API_KEY
```

For DeepSeek, the default hosted model is `deepseek-v4-flash` and the default
base URL is `https://api.deepseek.com`. You can override the model with
`deepseek-v4-pro` as the positional model argument, or set `DEEPSEEK_API_KEY`
in `poc/.env` instead of passing `--api-key` / `-ApiKey`.

### Direct Python execution (inside container):

```bash
python3 /app/src/packet_analyzer.py \
    --recording-id 1 \
    --mcp-url http://mcp-packet-db:8765 \
    --provider deepseek \
    --api-key YOUR_DEEPSEEK_API_KEY \
    --model deepseek-v4-flash \
    -v
```

## Command Line Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `-r, --recording-id` | Yes | - | Recording ID to analyze |
| `--mcp-url` | No | http://localhost:8765 | MCP packet-db server URL |
| `--provider` | No | ollama | LLM provider: ollama, gemini, openai, or deepseek |
| `--api-key` | No | - | API key for gemini/openai/deepseek |
| `--api-base-url` | No | provider default | Override API base URL for OpenAI-compatible providers |
| `--model` | No | provider default | Model name |
| `--ollama-host` | No | http://localhost:11434 | Ollama server URL |
| `-v, --verbose` | No | - | Enable debug logging |

## Available Models

You can use any Ollama-compatible model for local inference, or a supported hosted provider model. Some suggestions:

- `qwen3:8b` (default, ~5.5GB) - Strong reasoning with built-in thinking mode
- `deepseek-r1:8b` (~5.5GB) - Dedicated reasoning model, distilled from DeepSeek R1
- `qwen3:4b` (~2.8GB) - Lighter Qwen3 variant, faster but less accurate
- `llama3.1:8b-instruct-q4_K_M` (~4.7GB) - Good general-purpose alternative
- `deepseek-v4-flash` - DeepSeek API default
- `deepseek-v4-pro` - DeepSeek API stronger hosted model

## Output

The analyzer creates events in the database and assigns packets to them after
validating LLM decisions. Events are stored in the `event` table and packet-event
relationships in the `packet_event` table.

### Statistics

At the end of analysis, a summary is printed:
- Total packets processed
- Packets skipped (no payload, not HTTP)
- Packets assigned to existing events
- New events created
- Errors encountered

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   PostgreSQL    │◄────│  PacketAnalyzer │────►│     Ollama      │
│   (packets,     │     │   (LangChain)   │     │  (Local LLM)    │
│    events)      │     │                 │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```
