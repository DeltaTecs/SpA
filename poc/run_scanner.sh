#!/bin/bash
# Run vulnerability scanner phase one in the scanner container.

if [ $# -lt 1 ]; then
    echo "Usage: $0 <event_id> [model_name] [--app-details <path>] [--user-intend <path>] [--provider <ollama|gemini|openai|deepseek>] [--api-key <key>] [--api-base-url <url>] [--output <container_path>]"
    echo "  event_id       - The database event ID to summarize (required)"
    echo "  model_name     - Model to use (optional, default depends on provider)"
    echo "  --app-details  - Path to app_details.txt (optional)"
    echo "  --user-intend  - Path to user_intend.txt (optional)"
    echo "  --provider     - LLM provider: ollama, gemini, openai, or deepseek (optional, default: ollama)"
    echo "  --api-key      - API key for the chosen provider (required for gemini/openai/deepseek)"
    echo "  --api-base-url - Override API base URL for OpenAI-compatible providers (optional)"
    echo "  --output       - Optional container path for Markdown output"
    echo ""
    echo "Example:"
    echo "  $0 7"
    echo "  $0 7 qwen3:8b"
    echo "  $0 7 --provider deepseek --api-key YOUR_KEY"
    exit 1
fi

EVENT_ID="$1"
shift

MODEL=""
if [ $# -gt 0 ] && ! echo "$1" | grep -q '^--'; then
    MODEL="$1"
    shift
fi

APP_DETAILS=""
USER_INTEND=""
PROVIDER=""
API_KEY=""
API_BASE_URL=""
OUTPUT=""

while [ $# -gt 0 ]; do
    case "$1" in
        --app-details)
            APP_DETAILS="$2"
            shift 2
            ;;
        --user-intend)
            USER_INTEND="$2"
            shift 2
            ;;
        --provider)
            PROVIDER="$2"
            shift 2
            ;;
        --api-key)
            API_KEY="$2"
            shift 2
            ;;
        --api-base-url)
            API_BASE_URL="$2"
            shift 2
            ;;
        --model)
            MODEL="$2"
            shift 2
            ;;
        --output)
            OUTPUT="$2"
            shift 2
            ;;
        *)
            echo "Unknown argument: $1"
            exit 1
            ;;
    esac
done

SCANNER_CONTAINER="scanner-llm"

CLI_MODEL="$MODEL"
CLI_PROVIDER="$PROVIDER"
CLI_API_KEY="$API_KEY"
CLI_API_BASE_URL="$API_BASE_URL"
if [ -f "./.env" ]; then
    ENV_TMP="/tmp/scanner-dotenv.$$"
    tr -d '\r' < "./.env" > "$ENV_TMP"
    set -a
    . "$ENV_TMP"
    set +a
    rm -f "$ENV_TMP"
fi
if [ -n "$CLI_MODEL" ]; then
    MODEL="$CLI_MODEL"
fi
if [ -n "$CLI_PROVIDER" ]; then
    PROVIDER="$CLI_PROVIDER"
fi
if [ -n "$CLI_API_KEY" ]; then
    API_KEY="$CLI_API_KEY"
fi
if [ -n "$CLI_API_BASE_URL" ]; then
    API_BASE_URL="$CLI_API_BASE_URL"
fi

if [ "$PROVIDER" = "deepseek" ] && [ -z "$API_KEY" ] && [ -n "$DEEPSEEK_API_KEY" ]; then
    API_KEY="$DEEPSEEK_API_KEY"
fi
if [ "$PROVIDER" = "deepseek" ] && [ -z "$API_BASE_URL" ] && [ -n "$DEEPSEEK_API_BASE_URL" ]; then
    API_BASE_URL="$DEEPSEEK_API_BASE_URL"
fi

echo "Running scanner phase 1 for event $EVENT_ID..."

CONTAINER_DATA_DIR="/app/data"
docker exec "$SCANNER_CONTAINER" mkdir -p "$CONTAINER_DATA_DIR"

ENV_FLAGS=()
if [ -n "$APP_DETAILS" ]; then
    CONTAINER_PATH="$CONTAINER_DATA_DIR/app_details.txt"
    docker cp "$APP_DETAILS" "${SCANNER_CONTAINER}:${CONTAINER_PATH}"
    ENV_FLAGS+=("-e" "APP_DETAILS=$CONTAINER_PATH")
    echo "  App details: $APP_DETAILS -> $CONTAINER_PATH"
fi
if [ -n "$USER_INTEND" ]; then
    CONTAINER_PATH="$CONTAINER_DATA_DIR/user_intend.txt"
    docker cp "$USER_INTEND" "${SCANNER_CONTAINER}:${CONTAINER_PATH}"
    ENV_FLAGS+=("-e" "USER_INTEND=$CONTAINER_PATH")
    echo "  User intend: $USER_INTEND -> $CONTAINER_PATH"
fi
if [ -n "$PROVIDER" ]; then
    ENV_FLAGS+=("-e" "PROVIDER=$PROVIDER")
    echo "  Provider: $PROVIDER"
fi
if [ -n "$API_KEY" ]; then
    ENV_FLAGS+=("-e" "API_KEY=$API_KEY")
    echo "  API key: (set)"
fi
if [ -n "$API_BASE_URL" ]; then
    ENV_FLAGS+=("-e" "API_BASE_URL=$API_BASE_URL")
    echo "  API base URL: $API_BASE_URL"
fi
if [ -n "$OUTPUT" ]; then
    ENV_FLAGS+=("-e" "OUTPUT=$OUTPUT")
    echo "  Output: $OUTPUT"
fi

CMD="/app/run_scanner_internal.sh $EVENT_ID"
if [ -n "$MODEL" ]; then
    CMD="$CMD $MODEL"
fi

docker exec -it "${ENV_FLAGS[@]}" "$SCANNER_CONTAINER" bash -c "$CMD"

if [ $? -ne 0 ]; then
    echo "Error: Scanner phase 1 failed."
    exit 1
fi

echo "Scanner phase 1 completed successfully."
