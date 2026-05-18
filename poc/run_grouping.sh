#!/bin/bash
# run_grouping.sh
# Run packet event assignment in the existing analysis container.

# Check for required arguments
if [ $# -lt 1 ]; then
    echo "Usage: $0 <recording_id> [model_name] [--app-details <path>] [--user-intend <path>] [--provider <ollama|gemini|openai|deepseek>] [--api-key <key>] [--api-base-url <url>] [--web-search]"
    echo "  recording_id   - The recording ID to analyze (required)"
    echo "  model_name     - Model to use (optional, default depends on provider)"
    echo "  --app-details  - Path to app_details.txt (optional)"
    echo "  --user-intend  - Path to user_intend.txt (optional)"
    echo "  --provider     - LLM provider: ollama, gemini, openai, or deepseek (optional, default: ollama)"
    echo "  --api-key      - API key for the chosen provider (required for gemini/openai/deepseek)"
    echo "  --api-base-url - Override API base URL for OpenAI-compatible providers (optional)"
    echo "  --web-search   - Enable the external web-search MCP tool (Tavily) during grouping (optional, default: off)"
    echo ""
    echo "Example:"
    echo "  $0 1"
    echo "  $0 1 qwen3:8b"
    echo "  $0 1 qwen3:8b --app-details /data/app_details.txt --user-intend /data/user_intend.txt"
    echo "  $0 1 --provider gemini --api-key YOUR_KEY"
    echo "  $0 1 --provider deepseek --api-key YOUR_KEY"
    echo "  $0 1 --provider openai --api-key YOUR_KEY --model gpt-4o-mini"
    echo "  $0 1 --web-search"
    exit 1
fi

RECORDING_ID="$1"
APP_DETAILS=""
USER_INTEND=""
PROVIDER=""
API_KEY=""
API_BASE_URL=""
WEB_SEARCH=0

shift
MODEL=""

# Parse optional positional model, then named arguments.
if [ -n "$1" ] && ! echo "$1" | grep -q '^--'; then
    MODEL="$1"
    shift
fi
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
        --web-search)
            WEB_SEARCH=1
            shift
            ;;
        *)
            shift
            ;;
    esac
done

# Container name
GROUPING_CONTAINER="grouping"

# Load environment from .env if available
if [ -f "./.env" ]; then
    ENV_TMP="/tmp/dotenv.$$"
    tr -d '\r' < "./.env" > "$ENV_TMP"
    set -a
    . "$ENV_TMP"
    set +a
    rm -f "$ENV_TMP"
fi

if [ "$PROVIDER" = "deepseek" ] && [ -z "$API_KEY" ] && [ -n "$DEEPSEEK_API_KEY" ]; then
    API_KEY="$DEEPSEEK_API_KEY"
fi
if [ "$PROVIDER" = "deepseek" ] && [ -z "$API_BASE_URL" ] && [ -n "$DEEPSEEK_API_BASE_URL" ]; then
    API_BASE_URL="$DEEPSEEK_API_BASE_URL"
fi

echo "Running packet event assignment for recording $RECORDING_ID..."

# Container-internal directory for context files
CONTAINER_DATA_DIR="/app/data"

# Ensure data directory exists in container
docker exec "$GROUPING_CONTAINER" mkdir -p "$CONTAINER_DATA_DIR"

# Copy context files into the container and build env var flags
ENV_FLAGS=""
if [ -n "$APP_DETAILS" ]; then
    CONTAINER_PATH="$CONTAINER_DATA_DIR/app_details.txt"
    docker cp "$APP_DETAILS" "${GROUPING_CONTAINER}:${CONTAINER_PATH}"
    ENV_FLAGS="$ENV_FLAGS -e APP_DETAILS=$CONTAINER_PATH"
    echo "  App details: $APP_DETAILS -> $CONTAINER_PATH"
fi
if [ -n "$USER_INTEND" ]; then
    CONTAINER_PATH="$CONTAINER_DATA_DIR/user_intend.txt"
    docker cp "$USER_INTEND" "${GROUPING_CONTAINER}:${CONTAINER_PATH}"
    ENV_FLAGS="$ENV_FLAGS -e USER_INTEND=$CONTAINER_PATH"
    echo "  User intend: $USER_INTEND -> $CONTAINER_PATH"
fi
if [ -n "$PROVIDER" ]; then
    ENV_FLAGS="$ENV_FLAGS -e PROVIDER=$PROVIDER"
    echo "  Provider: $PROVIDER"
fi
if [ -n "$API_KEY" ]; then
    ENV_FLAGS="$ENV_FLAGS -e API_KEY=$API_KEY"
    echo "  API key: (set)"
fi
if [ -n "$API_BASE_URL" ]; then
    ENV_FLAGS="$ENV_FLAGS -e API_BASE_URL=$API_BASE_URL"
    echo "  API base URL: $API_BASE_URL"
fi
if [ "$WEB_SEARCH" = "1" ]; then
    ENV_FLAGS="$ENV_FLAGS -e GROUPING_ENABLE_WEB_SEARCH=1"
    echo "  Web search: enabled"
fi

# Build the command
CMD="/app/run_grouping_internal.sh $RECORDING_ID"
if [ -n "$MODEL" ]; then
    CMD="$CMD $MODEL"
fi

# Execute in container
docker exec -it $ENV_FLAGS "$GROUPING_CONTAINER" bash -c "$CMD"

if [ $? -ne 0 ]; then
    echo "Error: packet analysis failed."
    exit 1
fi

echo "Packet analysis completed successfully!"
