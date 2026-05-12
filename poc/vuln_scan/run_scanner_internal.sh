#!/bin/bash
# Internal script to run scanner phase one inside the scanner container.

set -e

MCP_URL="${MCP_URL:-http://mcp-packet-db:8765}"
MODEL="${MODEL:-}"
OLLAMA_HOST="${OLLAMA_HOST:-http://localhost:11434}"
APP_DETAILS="${APP_DETAILS:-}"
USER_INTEND="${USER_INTEND:-}"
PROVIDER="${PROVIDER:-ollama}"
API_KEY="${API_KEY:-}"
API_BASE_URL="${API_BASE_URL:-}"
SCANNER_VERBOSE="${SCANNER_VERBOSE:-0}"
OUTPUT="${OUTPUT:-}"

if [ "$PROVIDER" = "deepseek" ] && [ -z "$API_KEY" ] && [ -n "${DEEPSEEK_API_KEY:-}" ]; then
    API_KEY="$DEEPSEEK_API_KEY"
fi
if [ "$PROVIDER" = "deepseek" ] && [ -z "$API_BASE_URL" ] && [ -n "${DEEPSEEK_API_BASE_URL:-}" ]; then
    API_BASE_URL="$DEEPSEEK_API_BASE_URL"
fi

if [ -z "$1" ]; then
    echo "Usage: $0 <event_id> [model_name]"
    echo "  event_id    - The database event ID to summarize (required)"
    echo "  model_name  - Model to use (optional, default depends on provider)"
    exit 1
fi

EVENT_ID="$1"
if [ -n "$2" ]; then
    MODEL="$2"
fi

if [ -z "$MODEL" ]; then
    case "$PROVIDER" in
        gemini) MODEL="gemini-2.0-flash" ;;
        openai) MODEL="gpt-4o-mini" ;;
        deepseek) MODEL="deepseek-v4-flash" ;;
        *) MODEL="qwen3:8b" ;;
    esac
fi

echo "=========================================="
echo "Vulnerability Scanner Phase 1 Configuration"
echo "=========================================="
echo "Event ID: $EVENT_ID"
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
if [ -n "$OUTPUT" ]; then
    echo "Output: $OUTPUT"
fi
echo "Phase 2: TODO, not implemented"
echo "=========================================="

if [ "$PROVIDER" = "ollama" ]; then
    echo "Checking Ollama service..."
    if ! pgrep -f "ollama serve" > /dev/null; then
        echo "Starting Ollama service..."
        ollama serve > /tmp/ollama.log 2>&1 &

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

    echo "Ensuring model is available..."
    if ! ollama list | grep -q "$MODEL"; then
        echo "Pulling model $MODEL (this may take a while)..."
        ollama pull "$MODEL"
    else
        echo "Model $MODEL is already available."
    fi
fi

echo "Starting scanner phase 1..."
CMD_ARGS=(
    --event-id "$EVENT_ID"
    --mcp-url "$MCP_URL"
    --model "$MODEL"
    --provider "$PROVIDER"
)

if [ "$SCANNER_VERBOSE" != "0" ]; then
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
fi
if [ -n "$USER_INTEND" ]; then
    CMD_ARGS+=(--user-intend "$USER_INTEND")
fi
if [ -n "$OUTPUT" ]; then
    CMD_ARGS+=(--output "$OUTPUT")
fi

python3 /app/src/scanner.py "${CMD_ARGS[@]}"

echo "Scanner phase 1 complete. Phase 2 remains TODO."
