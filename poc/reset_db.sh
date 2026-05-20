#!/bin/bash
set -euo pipefail

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

echo "Resetting database..."
docker exec \
    -e "DB_HOST=$DB_HOST" \
    -e "DB_PORT=$DB_PORT" \
    -e "DB_NAME=$DB_NAME" \
    -e "DB_ADMIN_USER=$DB_ADMIN_USER" \
    -e "DB_ADMIN_PASSWORD=$DB_ADMIN_PASSWORD" \
    -e "DB_USER=$DB_USER" \
    -e "DB_PASSWORD=$DB_PASSWORD" \
    "$PROCESSOR_CONTAINER" python3 reset_db.py
