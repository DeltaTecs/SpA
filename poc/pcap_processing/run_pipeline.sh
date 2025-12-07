#!/bin/bash

# Hardcoded variables
PCAP_FILE="/app/parsing/resources/discord_room.pcapng"
KEYLOG_FILE="/app/parsing/resources/discord-room_keys.log"
FILTERED_PCAP="/tmp/filtered.pcap"

# DB Settings
DB_HOST="postgres"
DB_PORT="5432"
DB_NAME="main"
DB_USER="appuser"
DB_PASSWORD="appuser_password"

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
    --user "$DB_USER" \
    --password "$DB_PASSWORD" \
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
python3 parsing/post_processing.py \
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
