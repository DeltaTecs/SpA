#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat >&2 <<'EOF'
Usage:
  ./db/dump_load_db.sh dump <dump-file>
  ./db/dump_load_db.sh load <dump-file>

Creates or loads a PostgreSQL data-only dump using the Postgres Docker container.
Settings are read from ../.env relative to this script.
EOF
}

die() {
    echo "Error: $*" >&2
    exit 1
}

trim() {
    local value="$1"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s' "$value"
}

load_env() {
    local env_file="$1"
    local line key value

    [ -f "$env_file" ] || return 0

    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        line="$(trim "$line")"

        [ -n "$line" ] || continue
        [[ "$line" != \#* ]] || continue
        [[ "$line" == *=* ]] || continue

        key="$(trim "${line%%=*}")"
        value="$(trim "${line#*=}")"

        [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue

        if [[ "$value" == \"*\" && "$value" == *\" ]]; then
            value="${value:1:${#value}-2}"
        elif [[ "$value" == \'*\' && "$value" == *\' ]]; then
            value="${value:1:${#value}-2}"
        fi

        export "$key=$value"
    done < "$env_file"
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

docker_exec_pg() {
    PGPASSWORD="$DB_ADMIN_PASSWORD" docker exec -e PGPASSWORD "$DB_CONTAINER" "$@"
}

ensure_container_running() {
    local running

    if ! docker inspect "$DB_CONTAINER" >/dev/null 2>&1; then
        die "Docker container '$DB_CONTAINER' was not found. Start the stack from the poc directory first."
    fi

    running="$(docker inspect --format '{{.State.Running}}' "$DB_CONTAINER")"
    [ "$running" = "true" ] || die "Docker container '$DB_CONTAINER' is not running."
}

cleanup() {
    docker exec "$DB_CONTAINER" rm -f "$CONTAINER_DUMP" "$CONTAINER_LIST" "$CONTAINER_LIST.raw" "$CONTAINER_LIST.relations" >/dev/null 2>&1 || true
}

dump_db() {
    local dump_dir

    dump_dir="$(dirname -- "$DUMP_FILE")"
    mkdir -p "$dump_dir"

    echo "Dumping '$DB_NAME' from container '$DB_CONTAINER' to '$DUMP_FILE'..."
    docker_exec_pg \
        pg_dump \
        --host=127.0.0.1 \
        --port="$DB_PORT" \
        --username="$DB_ADMIN_USER" \
        --dbname="$DB_NAME" \
        --format=custom \
        --data-only \
        --no-owner \
        --no-privileges \
        --exclude-table-data=protocol \
        --file="$CONTAINER_DUMP"

    docker cp "$DB_CONTAINER:$CONTAINER_DUMP" "$DUMP_FILE"
    echo "Wrote dump to '$DUMP_FILE'."
}

create_restore_list() {
    docker_exec_pg sh -c '
        set -eu
        pg_restore -l "$1" > "$2.raw"
        psql \
            --host=127.0.0.1 \
            --port="$3" \
            --username="$4" \
            --dbname="$5" \
            --tuples-only \
            --no-align \
            --field-separator="|" \
            --command="SELECT n.nspname, c.relname, c.relkind FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.relkind IN ('\''r'\'', '\''p'\'', '\''f'\'', '\''S'\'');" \
            > "$2.relations"

        awk -F "|" '\''
            FNR == NR {
                key = $1 "." $2
                if ($3 == "S") {
                    sequences[key] = 1
                } else {
                    tables[key] = 1
                }
                next
            }

            / TABLE DATA public protocol / || / SEQUENCE SET public protocol_protocol_id_seq / {
                print ";" $0
                next
            }

            {
                split($0, parts, /[[:space:]]+/)

                if (parts[4] == "TABLE" && parts[5] == "DATA") {
                    key = parts[6] "." parts[7]
                    if (!(key in tables)) {
                        missing_tables += 1
                        missing_table_names[key] = 1
                        print ";" $0
                        next
                    }
                } else if (parts[4] == "SEQUENCE" && parts[5] == "SET") {
                    key = parts[6] "." parts[7]
                    if (!(key in sequences)) {
                        missing_sequences += 1
                        missing_sequence_names[key] = 1
                        print ";" $0
                        next
                    }
                }

                print
            }

            END {
                if (missing_tables > 0 || missing_sequences > 0) {
                    printf "Skipped %d table data item(s) and %d sequence set item(s) missing from the current database.\n", missing_tables, missing_sequences > "/dev/stderr"
                    if (missing_tables > 0) {
                        print "Skipped table data for missing table(s):" > "/dev/stderr"
                        for (name in missing_table_names) {
                            print "  - " name > "/dev/stderr"
                        }
                    }

                    if (missing_sequences > 0) {
                        print "Skipped sequence set for missing sequence(s):" > "/dev/stderr"
                        for (name in missing_sequence_names) {
                            print "  - " name > "/dev/stderr"
                        }
                    }
                }
            }
        '\'' "$2.relations" "$2.raw" > "$2"
        rm -f "$2.raw" "$2.relations"
    ' sh "$CONTAINER_DUMP" "$CONTAINER_LIST" "$DB_PORT" "$DB_ADMIN_USER" "$DB_NAME"
}

load_db() {
    [ -f "$DUMP_FILE" ] || die "dump file not found: $DUMP_FILE"

    echo "Loading '$DUMP_FILE' into '$DB_NAME' in container '$DB_CONTAINER'..."
    docker cp "$DUMP_FILE" "$DB_CONTAINER:$CONTAINER_DUMP"
    create_restore_list

    docker_exec_pg \
        pg_restore \
        --host=127.0.0.1 \
        --port="$DB_PORT" \
        --username="$DB_ADMIN_USER" \
        --dbname="$DB_NAME" \
        --data-only \
        --no-owner \
        --no-privileges \
        --disable-triggers \
        --single-transaction \
        --exit-on-error \
        --use-list="$CONTAINER_LIST" \
        "$CONTAINER_DUMP"

    echo "Loaded dump into '$DB_NAME'."
}

if [ "$#" -ne 2 ]; then
    usage
    exit 1
fi

ACTION="$1"
DUMP_FILE="$2"

case "$ACTION" in
    dump|load) ;;
    *)
        usage
        die "unknown action: $ACTION"
        ;;
esac

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
load_env "$POC_DIR/.env"

DB_CONTAINER="${DB_CONTAINER_NAME:-db}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-main}"
DB_ADMIN_USER="${DB_ADMIN_USER:-dbadmin}"
DB_ADMIN_PASSWORD="${DB_ADMIN_PASSWORD:-dbadmin}"
SAFE_DB_NAME="${DB_NAME//[^A-Za-z0-9_.-]/_}"
CONTAINER_DUMP="/tmp/dump_load_db_${SAFE_DB_NAME}_$$.dump"
CONTAINER_LIST="/tmp/dump_load_db_${SAFE_DB_NAME}_$$.list"

require_command docker
ensure_container_running
trap cleanup EXIT

case "$ACTION" in
    dump) dump_db ;;
    load) load_db ;;
esac
