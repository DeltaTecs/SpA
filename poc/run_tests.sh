#!/bin/bash

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

echo "Running test_ssl_decryptor..."
docker exec "$PROCESSOR_CONTAINER" python3 -m unittest util/test/test_ssl_decryptor.py

echo "Running test_parsing..."
docker exec "${DB_ENV_ARGS[@]}" "$PROCESSOR_CONTAINER" python3 -m unittest parsing/test/test_parsing.py

echo "Running test_post_processing..."
docker exec "${DB_ENV_ARGS[@]}" "$PROCESSOR_CONTAINER" python3 -m unittest parsing/test/test_post_processing.py

echo "Running test_mcp_packet_db_server..."
docker compose run --rm --build mcp-packet-db python -m unittest discover -s /app/test

echo "Running test_mcp_hexstrike..."
docker compose run --rm --build --no-deps --entrypoint /opt/hexstrike-venv/bin/python mcp-hexstrike -m unittest discover -s /app/test
