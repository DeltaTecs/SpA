#!/bin/bash
# run_grouping_internal.sh
# Internal script to run packet event assignment inside the existing container.

set -e

# Default values (can be overridden by environment variables)
MCP_URL="${MCP_URL:-http://mcp-packet-db:8765}"
MODEL="${MODEL:-}"
OLLAMA_HOST="${OLLAMA_HOST:-http://localhost:11434}"
APP_DETAILS="${APP_DETAILS:-}"
USER_INTEND="${USER_INTEND:-}"
PROVIDER="${PROVIDER:-ollama}"
API_KEY="${API_KEY:-}"
API_BASE_URL="${API_BASE_URL:-}"
GROUPING_VERBOSE="${GROUPING_VERBOSE:-0}"

if [ "$PROVIDER" = "deepseek" ] && [ -z "$API_KEY" ] && [ -n "${DEEPSEEK_API_KEY:-}" ]; then
    API_KEY="$DEEPSEEK_API_KEY"
fi
if [ "$PROVIDER" = "deepseek" ] && [ -z "$API_BASE_URL" ] && [ -n "${DEEPSEEK_API_BASE_URL:-}" ]; then
    API_BASE_URL="$DEEPSEEK_API_BASE_URL"
fi

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

# Resolve default model based on provider
if [ -z "$MODEL" ]; then
    case "$PROVIDER" in
        gemini)  MODEL="gemini-2.0-flash" ;;
        openai)  MODEL="gpt-4o-mini" ;;
        deepseek) MODEL="deepseek-v4-flash" ;;
        *)       MODEL="qwen3:8b" ;;
    esac
fi

echo "=========================================="
echo "Packet Analysis Configuration"
echo "=========================================="
echo "Recording ID: $RECORDING_ID"
echo "MCP Server: $MCP_URL"
echo "Provider: $PROVIDER"
echo "Model: $MODEL"
if [ "$PROVIDER" = "ollama" ]; then
    echo "Ollama Host: $OLLAMA_HOST"
fi
if [ -n "$API_KEY" ]; then
    echo "API Key: (set)"
fi
if [ -n "$API_BASE_URL" ]; then
    echo "API Base URL: $API_BASE_URL"
fi
if [ -n "$APP_DETAILS" ]; then
    echo "App Details: $APP_DETAILS"
fi
if [ -n "$USER_INTEND" ]; then
    echo "User Intend: $USER_INTEND"
fi
echo "=========================================="

# Ollama setup (only needed when using the ollama provider)
if [ "$PROVIDER" = "ollama" ]; then
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
fi

# Run the analysis
echo "Starting packet event assignment..."
CMD_ARGS=(
    --recording-id "$RECORDING_ID"
    --mcp-url "$MCP_URL"
    --model "$MODEL"
    --provider "$PROVIDER"
)

if [ "$GROUPING_VERBOSE" != "0" ]; then
    CMD_ARGS+=(-v)
fi

if [ "$PROVIDER" = "ollama" ]; then
    CMD_ARGS+=(--ollama-host "$OLLAMA_HOST")
fi
if [ -n "$API_KEY" ]; then
    CMD_ARGS+=(--api-key "$API_KEY")
fi
if [ -n "$API_BASE_URL" ]; then
    CMD_ARGS+=(--api-base-url "$API_BASE_URL")
fi
if [ -n "$APP_DETAILS" ]; then
    CMD_ARGS+=(--app-details "$APP_DETAILS")
    echo "App details: $APP_DETAILS"
fi
if [ -n "$USER_INTEND" ]; then
    CMD_ARGS+=(--user-intend "$USER_INTEND")
    echo "User intend: $USER_INTEND"
fi

python3 /app/src/packet_analyzer.py "${CMD_ARGS[@]}"

echo "Packet analysis complete!"
