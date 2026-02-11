#!/bin/bash
# run_grouping_internal.sh
# Internal script to run the packet grouping inside the grouping container

set -e

# Default values (can be overridden by environment variables)
MCP_URL="${MCP_URL:-http://mcp-packet-db:8765}"
MODEL="${MODEL:-qwen3:8b}"
OLLAMA_HOST="${OLLAMA_HOST:-http://localhost:11434}"
APP_DETAILS="${APP_DETAILS:-}"
USER_INTEND="${USER_INTEND:-}"

# Recording ID is required
if [ -z "$1" ]; then
    echo "Usage: $0 <recording_id> [model_name]"
    echo "  recording_id  - The recording ID to analyze (required)"
    echo "  model_name    - Ollama model to use (optional, default: $MODEL)"
    exit 1
fi

RECORDING_ID="$1"
if [ -n "$2" ]; then
    MODEL="$2"
fi

echo "=========================================="
echo "Packet Grouping Configuration"
echo "=========================================="
echo "Recording ID: $RECORDING_ID"
echo "MCP Server: $MCP_URL"
echo "Model: $MODEL"
echo "Ollama Host: $OLLAMA_HOST"
if [ -n "$APP_DETAILS" ]; then
    echo "App Details: $APP_DETAILS"
fi
if [ -n "$USER_INTEND" ]; then
    echo "User Intend: $USER_INTEND"
fi
echo "=========================================="

# Ensure Ollama is running
echo "Checking Ollama service..."
if ! pgrep -f "ollama serve" > /dev/null; then
    echo "Starting Ollama service..."
    ollama serve > /tmp/ollama.log 2>&1 &
    
    # Wait for Ollama to be ready (up to 30 seconds)
    echo "Waiting for Ollama to be ready..."
    for i in {1..30}; do
        if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
            echo "Ollama is ready!"
            break
        fi
        if [ $i -eq 30 ]; then
            echo "ERROR: Ollama failed to start. Check /tmp/ollama.log"
            cat /tmp/ollama.log
            exit 1
        fi
        sleep 1
    done
else
    echo "Ollama is already running."
fi

# Pull the model if not available
echo "Ensuring model is available..."
if ! ollama list | grep -q "$MODEL"; then
    echo "Pulling model $MODEL (this may take a while)..."
    ollama pull "$MODEL"
else
    echo "Model $MODEL is already available."
fi

# Run the analysis
echo "Starting packet grouping..."
CMD_ARGS=(
    --recording-id "$RECORDING_ID"
    --mcp-url "$MCP_URL"
    --model "$MODEL"
    --ollama-host "$OLLAMA_HOST"
    -v
)

if [ -n "$APP_DETAILS" ]; then
    CMD_ARGS+=(--app-details "$APP_DETAILS")
    echo "App details: $APP_DETAILS"
fi
if [ -n "$USER_INTEND" ]; then
    CMD_ARGS+=(--user-intend "$USER_INTEND")
    echo "User intend: $USER_INTEND"
fi

python3 /app/packet_analyzer.py "${CMD_ARGS[@]}"

echo "Grouping complete!"
