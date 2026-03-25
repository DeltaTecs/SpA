# Packet Grouping / Analysis Module

This module analyzes network packets using a local LLM (via Ollama) and groups them into application-specific events.

## Overview

The packet analyzer uses LangChain with Ollama to:
1. Load packets from the database for a specific recording
2. For each packet with payload (or HTTP headers), prepare a prompt with:
   - Packet payload in hex format
   - Protocol layers (e.g., IP|TCP|TLS|HTTP)
   - Connection stream (source/destination IP:port)
   - Entropy value (normalized 0-1)
   - List of existing events
3. Use the LLM to determine if the packet belongs to an existing event or requires a new one
4. Update the database with event assignments

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
./run_analysis.sh <recording_id> [model_name]

# PowerShell/Windows
.\run_analysis.ps1 -RecordingId <recording_id> [-Model <model_name>]
```

### Examples:

```bash
# Analyze recording 1 with default model
./run_analysis.sh 1

# Analyze recording 2 with a specific model
./run_analysis.sh 2 qwen3:8b
```

### Direct Python execution (inside container):

```bash
python3 /app/packet_analyzer.py \
    --recording-id 1 \
    --db-host postgres \
    --db-port 5432 \
    --db-name main \
    --db-user appuser \
    --db-password appuser_password \
    --model qwen3:8b \
    --ollama-host http://localhost:11434 \
    -v
```

## Command Line Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `-r, --recording-id` | Yes | - | Recording ID to analyze |
| `--db-host` | No | localhost | Database host |
| `--db-port` | No | 5432 | Database port |
| `--db-name` | No | main | Database name |
| `--db-user` | No | appuser | Database user |
| `--db-password` | No | appuser_password | Database password |
| `--model` | No | qwen3:8b | Ollama model name |
| `--ollama-host` | No | http://localhost:11434 | Ollama server URL |
| `-v, --verbose` | No | - | Enable debug logging |

## Available Models

You can use any Ollama-compatible model. Some suggestions:

- `qwen3:8b` (default, ~5.5GB) - Strong reasoning with built-in thinking mode
- `deepseek-r1:8b` (~5.5GB) - Dedicated reasoning model, distilled from DeepSeek R1
- `qwen3:4b` (~2.8GB) - Lighter Qwen3 variant, faster but less accurate
- `llama3.1:8b-instruct-q4_K_M` (~4.7GB) - Good general-purpose alternative

## Output

The analyzer creates events in the database and assigns packets to them. Events are stored in the `event` table and packet-event relationships in `packet_event` table.

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
