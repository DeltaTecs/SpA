#!/bin/bash
# run_grouping_internal.sh
# Internal script to run the packet grouping inside the grouping container

set -e

# Default values (can be overridden by environment variables)
DB_HOST="${DB_HOST:-postgres}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-main}"
DB_USER="${DB_USER:-appuser}"
DB_PASSWORD="${DB_PASSWORD:-appuser_password}"
MODEL="${MODEL:-llama3.2:3b-instruct-q4_K_M}"
OLLAMA_HOST="${OLLAMA_HOST:-http://localhost:11434}"

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
echo "Database: $DB_HOST:$DB_PORT/$DB_NAME"
echo "Model: $MODEL"
echo "Ollama Host: $OLLAMA_HOST"
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
python3 /app/packet_analyzer.py \
    --recording-id "$RECORDING_ID" \
    --db-host "$DB_HOST" \
    --db-port "$DB_PORT" \
    --db-name "$DB_NAME" \
    --db-user "$DB_USER" \
    --db-password "$DB_PASSWORD" \
    --model "$MODEL" \
    --ollama-host "$OLLAMA_HOST" \
    -v

echo "Grouping complete!"
