#!/bin/bash
# run_grouping.sh
# Run packet grouping in the grouping container

# Check for required arguments
if [ $# -lt 1 ]; then
    echo "Usage: $0 <recording_id> [model_name] [--app-details <path>] [--user-intend <path>] [--provider <ollama|gemini|openai>] [--api-key <key>]"
    echo "  recording_id   - The recording ID to analyze (required)"
    echo "  model_name     - Model to use (optional, default depends on provider)"
    echo "  --app-details  - Path to app_details.txt (optional)"
    echo "  --user-intend  - Path to user_intend.txt (optional)"
    echo "  --provider     - LLM provider: ollama, gemini, or openai (optional, default: ollama)"
    echo "  --api-key      - API key for the chosen provider (required for gemini/openai)"
    echo ""
    echo "Example:"
    echo "  $0 1"
    echo "  $0 1 qwen3:8b"
    echo "  $0 1 qwen3:8b --app-details /data/app_details.txt --user-intend /data/user_intend.txt"
    echo "  $0 1 --provider gemini --api-key YOUR_KEY"
    echo "  $0 1 --provider openai --api-key YOUR_KEY --model gpt-4o-mini"
    exit 1
fi

RECORDING_ID="$1"
MODEL="${2:-}"
APP_DETAILS=""
USER_INTEND=""
PROVIDER=""
API_KEY=""

# Parse optional named arguments
shift
if [ -n "$1" ] && ! echo "$1" | grep -q '^--'; then
    shift  # skip model positional arg
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

echo "Running packet grouping for recording $RECORDING_ID..."

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

# Build the command
CMD="/app/run_grouping_internal.sh $RECORDING_ID"
if [ -n "$MODEL" ]; then
    CMD="$CMD $MODEL"
fi

# Execute in container
docker exec -it $ENV_FLAGS "$GROUPING_CONTAINER" bash -c "$CMD"

if [ $? -ne 0 ]; then
    echo "Error: Grouping failed."
    exit 1
fi

echo "Packet grouping completed successfully!"
