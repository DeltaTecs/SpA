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
FILTERED_PCAP="/tmp/filtered.pcap"

# DB settings are provided by docker compose environment or wrapper scripts.
if [ -f "/app/.env" ]; then
    ENV_TMP="/tmp/dotenv.$$"
    tr -d '\r' < "/app/.env" > "$ENV_TMP"
    set -a
    . "$ENV_TMP"
    set +a
    rm -f "$ENV_TMP"
fi

: "${DB_HOST:?Missing DB_HOST environment variable}"
: "${DB_PORT:?Missing DB_PORT environment variable}"
: "${DB_NAME:?Missing DB_NAME environment variable}"
: "${DB_ADMIN_USER:?Missing DB_ADMIN_USER environment variable}"
: "${DB_ADMIN_PASSWORD:?Missing DB_ADMIN_PASSWORD environment variable}"
: "${DB_USER:?Missing DB_USER environment variable}"
: "${DB_PASSWORD:?Missing DB_PASSWORD environment variable}"

# Ensure we are in /app
cd /app

echo "----------------------------------------------------------------"
echo "Starting Pipeline"
echo "PCAP: $PCAP_FILE"
echo "Keylog: $KEYLOG_FILE"
echo "----------------------------------------------------------------"

# 1. Pre-processing
echo "[1/4] Running Pre-processing..."
#if [ -f "$PCAP_FILE" ]; then
#    python3 parsing/pre_processing.py "$PCAP_FILE" "$FILTERED_PCAP"
#    if [ $? -ne 0 ]; then
#        echo "Error: Pre-processing failed."
#        exit 1
#    fi
#else
#    echo "Error: PCAP file not found at $PCAP_FILE"
#    exit 1
#fi
FILTERED_PCAP="$PCAP_FILE"

# 2. Reset DB
echo "[2/4] Resetting Database..."
python3 reset_db.py \
    --host "$DB_HOST" \
    --port "$DB_PORT" \
    --dbname "$DB_NAME" \
    --user "$DB_ADMIN_USER" \
    --password "$DB_ADMIN_PASSWORD" \
    --runtime-user "$DB_USER" \
    --runtime-password "$DB_PASSWORD" \
    --init-sql "db/init_db.sql"

if [ $? -ne 0 ]; then
    echo "Error: DB Reset failed."
    exit 1
fi

# 3. Pcap to DB
echo "[3/4] Importing PCAP to DB..."
# Construct command
CMD="python3 parsing/pcap_to_db.py -i \"$FILTERED_PCAP\" -n \"Recording 1\" --db-host \"$DB_HOST\" --db-port \"$DB_PORT\" --db-name \"$DB_NAME\" --db-user \"$DB_USER\" --db-password \"$DB_PASSWORD\""

if [ -n "$KEYLOG_FILE" ]; then
    if [ -f "$KEYLOG_FILE" ]; then
        CMD="$CMD --sslkeylog \"$KEYLOG_FILE\""
    else
        echo "Warning: Keylog file specified but not found at $KEYLOG_FILE. Proceeding without decryption."
    fi
fi

echo "Executing: $CMD"
eval $CMD

if [ $? -ne 0 ]; then
    echo "Error: Pcap to DB failed."
    exit 1
fi

# 4. Post-processing
echo "[4/4] Running Post-processing..."
python3 parsing/post_processing/post_processing.py \
    --recording-id 1 \
    --db-host "$DB_HOST" \
    --db-port "$DB_PORT" \
    --db-name "$DB_NAME" \
    --db-user "$DB_USER" \
    --db-password "$DB_PASSWORD"

if [ $? -ne 0 ]; then
    echo "Error: Post-processing failed."
    exit 1
fi

echo "----------------------------------------------------------------"
echo "Pipeline Completed Successfully."
echo "----------------------------------------------------------------"
