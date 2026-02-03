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

# Container paths
CONTAINER_PCAP="/tmp/input.pcapng"
CONTAINER_KEYLOG="/tmp/keylog.log"

echo "Running full pipeline (Pre-processing -> Reset DB -> Import -> Post-processing)..."

# Copy PCAP file to container
echo "Copying PCAP file to container..."
docker cp "$PCAP_FILE" pcap-processor:"$CONTAINER_PCAP"
if [ $? -ne 0 ]; then
    echo "Error: Failed to copy PCAP file to container."
    exit 1
fi

# Build command arguments
CMD_ARGS="$CONTAINER_PCAP"

# Copy keylog file if provided
if [ -n "$KEYLOG_FILE" ]; then
    echo "Copying keylog file to container..."
    docker cp "$KEYLOG_FILE" pcap-processor:"$CONTAINER_KEYLOG"
    if [ $? -ne 0 ]; then
        echo "Error: Failed to copy keylog file to container."
        exit 1
    fi
    CMD_ARGS="$CMD_ARGS $CONTAINER_KEYLOG"
fi

# Run the internal pipeline script
if [ -n "$KEYLOG_FILE" ]; then
    docker exec -it pcap-processor bash /app/run_pipeline_internal.sh "$CONTAINER_PCAP" "$CONTAINER_KEYLOG"
else
    docker exec -it pcap-processor bash /app/run_pipeline_internal.sh "$CONTAINER_PCAP"
fi
