#!/bin/bash
# run_grouping.sh
# Run packet grouping in the grouping container

# Check for required arguments
if [ $# -lt 1 ]; then
    echo "Usage: $0 <recording_id> [model_name]"
    echo "  recording_id  - The recording ID to analyze (required)"
    echo "  model_name    - Ollama model to use (optional, default: qwen3:8b)"
    echo ""
    echo "Example:"
    echo "  $0 1"
    echo "  $0 1 qwen3:8b"
    exit 1
fi

RECORDING_ID="$1"
MODEL="${2:-}"

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

# Build the command
CMD="/app/run_grouping_internal.sh $RECORDING_ID"
if [ -n "$MODEL" ]; then
    CMD="$CMD $MODEL"
fi

# Execute in container
docker exec -it "$GROUPING_CONTAINER" bash -c "$CMD"

if [ $? -ne 0 ]; then
    echo "Error: Grouping failed."
    exit 1
fi

echo "Packet grouping completed successfully!"
