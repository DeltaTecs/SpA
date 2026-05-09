# Packet Purpose Analysis Module

This module connects to the packet-db MCP server, iterates over every packet in
one recording, and asks a LangChain chat model what each packet is likely doing.

The analyzer is read-only. It does not create events, assign packets, or mutate
the database.

## Flow

1. Connect to the MCP packet-db server.
2. Load packet IDs for the selected recording.
3. Fetch `packet_info` for each packet in capture order.
4. Ask the LLM for a concise purpose, evidence summary, and uncertainty.
5. Print one result block per packet.

## Requirements

- Docker with NVIDIA GPU support when using local Ollama
- PostgreSQL database with packets already imported
- MCP packet-db server reachable from the analysis container

## Usage

From the `poc` directory:

```bash
./run_grouping.sh <recording_id> [model_name]
```

PowerShell:

```powershell
.\run_grouping.ps1 -RecordingId <recording_id> [-Model <model_name>]
```

Examples:

```bash
./run_grouping.sh 1
./run_grouping.sh 2 qwen3:8b
./run_grouping.sh 1 --provider deepseek --api-key YOUR_DEEPSEEK_API_KEY
```

Direct execution inside the container:

```bash
python3 /app/src/packet_analyzer.py \
    --recording-id 1 \
    --mcp-url http://mcp-packet-db:8765 \
    --provider deepseek \
    --api-key YOUR_DEEPSEEK_API_KEY \
    --model deepseek-v4-flash
```

## Output

Each packet prints a block like:

```text
=== packet 3/128 | packet_id:42 ===
Purpose: This packet appears to request updated channel metadata.
Evidence: HTTP method/path and neighboring response indicate metadata fetch.
Uncertainty: medium because payload details are partial.
```
