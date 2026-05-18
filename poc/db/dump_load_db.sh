#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:-}"
FILE="${2:-}"
POC_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ENV_FILE:-"${POC_ROOT}/.env"}"

usage() {
  echo "Usage: $(basename "$0") dump|load <file>" >&2
  echo "  Reads settings from: $ENV_FILE" >&2
  echo "  dump uses DB_USER; load uses DB_ADMIN_USER" >&2
}

if [[ -z "$ACTION" || -z "$FILE" ]]; then
  usage
  exit 2
fi

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Missing .env file: $ENV_FILE" >&2
  exit 1
fi

set -a
ENV_TMP="/tmp/dotenv.$$"
tr -d '\r' < "$ENV_FILE" > "$ENV_TMP"
source "$ENV_TMP"
rm -f "$ENV_TMP"
set +a

: "${DB_CONTAINER_NAME:?Missing DB_CONTAINER_NAME in $ENV_FILE}"
: "${DB_NAME:?Missing DB_NAME in $ENV_FILE}"
: "${DB_USER:?Missing DB_USER in $ENV_FILE}"
: "${DB_PASSWORD:?Missing DB_PASSWORD in $ENV_FILE}"
: "${DB_ADMIN_USER:?Missing DB_ADMIN_USER in $ENV_FILE}"
: "${DB_ADMIN_PASSWORD:?Missing DB_ADMIN_PASSWORD in $ENV_FILE}"
: "${DB_HOST:?Missing DB_HOST in $ENV_FILE}"
: "${DB_PORT:?Missing DB_PORT in $ENV_FILE}"

CONTAINER_NAME="$DB_CONTAINER_NAME"

exec_in_postgres() {
  local password="$1"
  local command="$2"
  docker exec \
    -e "PGPASSWORD=${password}" \
    -e "POSTGRES_USER=${DB_ADMIN_USER}" \
    -e "POSTGRES_DB=${DB_NAME}" \
    -e "DB_USER=${DB_USER}" \
    -e "DB_PASSWORD=${DB_PASSWORD}" \
    "${CONTAINER_NAME}" sh -lc "$command"
}

if [[ "$FILE" != /* ]]; then
  # Heuristic: paths like ./db/... are intended to be relative to the `poc` directory
  if [[ "$FILE" == db/* || "$FILE" == ./db/* ]]; then
    FILE="${POC_ROOT}/${FILE}"
  fi
fi

mkdir -p "$(dirname "$FILE")" 2>/dev/null || true

case "$ACTION" in
  dump)
    ACTION_DB_USER="${DB_USER}"
    ACTION_DB_PASSWORD="${DB_PASSWORD}"
    TMP="/tmp/${DB_NAME}_dump.dump"
    echo "Dumping database '${DB_NAME}' from container '${CONTAINER_NAME}' to '${FILE}'..."
    rm -f "$FILE" || true
    exec_in_postgres "$ACTION_DB_PASSWORD" "pg_dump -U '${ACTION_DB_USER}' -d '${DB_NAME}' -Fc -f '${TMP}'"
    docker cp "${CONTAINER_NAME}:${TMP}" "$FILE"
    exec_in_postgres "$ACTION_DB_PASSWORD" "rm -f '${TMP}'"
    echo "Done."
    ;;

  load)
    ACTION_DB_USER="${DB_ADMIN_USER}"
    ACTION_DB_PASSWORD="${DB_ADMIN_PASSWORD}"
    if [[ ! -f "$FILE" ]]; then
      echo "Input file not found: $FILE" >&2
      exit 1
    fi
    EXT="${FILE##*.}"
    if [[ "$EXT" == "$FILE" ]]; then
      echo "Dump file must have an extension (.dump/.backup/.tar or .sql): $FILE" >&2
      exit 1
    fi

    TMP="/tmp/${DB_NAME}_restore.${EXT}"
    echo "Loading dump '${FILE}' into database '${DB_NAME}' (overwriting) in container '${CONTAINER_NAME}'..."

    docker cp "$FILE" "${CONTAINER_NAME}:${TMP}"

    exec_in_postgres "$ACTION_DB_PASSWORD" "psql -U '${ACTION_DB_USER}' -d '${DB_NAME}' -v ON_ERROR_STOP=1 -c 'DROP SCHEMA public CASCADE; CREATE SCHEMA public;'"

    if [[ "${EXT,,}" == "sql" ]]; then
      exec_in_postgres "$ACTION_DB_PASSWORD" "psql -U '${ACTION_DB_USER}' -d '${DB_NAME}' -v ON_ERROR_STOP=1 -f '${TMP}'"
    else
      exec_in_postgres "$ACTION_DB_PASSWORD" "pg_restore -U '${ACTION_DB_USER}' -d '${DB_NAME}' --no-owner --no-privileges --exit-on-error '${TMP}'"
    fi

    exec_in_postgres "$ACTION_DB_PASSWORD" "rm -f '${TMP}'"
    echo "Done."
    ;;

  *)
    usage
    exit 2
    ;;
esac
