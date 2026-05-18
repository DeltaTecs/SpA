#!/bin/bash

# Check for required arguments
if [ $# -lt 1 ]; then
    echo "Usage: $0 <PCAP_FILE> [KEYLOG_FILE]"
    echo "  PCAP_FILE   - Path to the pcap file (required)"
    echo "  KEYLOG_FILE - Path to the SSL keylog file (optional)"
    exit 1
fi

PCAP_FILE="$1"
KEYLOG_FILE="${2:-}"

# Optional: use container name from .env
PROCESSOR_CONTAINER="pcap-processor"
if [ -f "./.env" ]; then
    ENV_TMP="/tmp/dotenv.$$"
    tr -d '\r' < "./.env" > "$ENV_TMP"
    set -a
    . "$ENV_TMP"
    set +a
    rm -f "$ENV_TMP"
    if [ -n "${PCAP_PROCESSOR_CONTAINER_NAME:-}" ]; then
        PROCESSOR_CONTAINER="$PCAP_PROCESSOR_CONTAINER_NAME"
    fi
fi

DB_HOST="${DB_HOST:-db}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-main}"
DB_ADMIN_USER="${DB_ADMIN_USER:-dbadmin}"
DB_ADMIN_PASSWORD="${DB_ADMIN_PASSWORD:-dbadmin}"
DB_USER="${DB_USER:-dbuser}"
DB_PASSWORD="${DB_PASSWORD:-dbuser}"
DB_ENV_ARGS=(
    -e "DB_HOST=$DB_HOST"
    -e "DB_PORT=$DB_PORT"
    -e "DB_NAME=$DB_NAME"
    -e "DB_ADMIN_USER=$DB_ADMIN_USER"
    -e "DB_ADMIN_PASSWORD=$DB_ADMIN_PASSWORD"
    -e "DB_USER=$DB_USER"
    -e "DB_PASSWORD=$DB_PASSWORD"
)

# Container paths
CONTAINER_PCAP="/tmp/input.pcapng"
CONTAINER_KEYLOG="/tmp/keylog.log"

echo "Running full pipeline (Pre-processing -> Reset DB -> Import -> Post-processing)..."

# Copy PCAP file to container
echo "Copying PCAP file to container..."
docker cp "$PCAP_FILE" "$PROCESSOR_CONTAINER":"$CONTAINER_PCAP"
if [ $? -ne 0 ]; then
    echo "Error: Failed to copy PCAP file to container."
    exit 1
fi

# Build command arguments
CMD_ARGS="$CONTAINER_PCAP"

# Copy keylog file if provided
if [ -n "$KEYLOG_FILE" ]; then
    echo "Copying keylog file to container..."
    docker cp "$KEYLOG_FILE" "$PROCESSOR_CONTAINER":"$CONTAINER_KEYLOG"
    if [ $? -ne 0 ]; then
        echo "Error: Failed to copy keylog file to container."
        exit 1
    fi
    CMD_ARGS="$CMD_ARGS $CONTAINER_KEYLOG"
fi

# Run the internal pipeline script
if [ -n "$KEYLOG_FILE" ]; then
    docker exec -it "${DB_ENV_ARGS[@]}" "$PROCESSOR_CONTAINER" bash /app/run_pipeline_internal.sh "$CONTAINER_PCAP" "$CONTAINER_KEYLOG"
else
    docker exec -it "${DB_ENV_ARGS[@]}" "$PROCESSOR_CONTAINER" bash /app/run_pipeline_internal.sh "$CONTAINER_PCAP"
fi
