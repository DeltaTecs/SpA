#!/usr/bin/env bash
set -euo pipefail

HEXSTRIKE_HOME="${HEXSTRIKE_HOME:-/opt/hexstrike-ai}"
HEXSTRIKE_VENV="${HEXSTRIKE_VENV:-/opt/hexstrike-venv}"
HEXSTRIKE_MODE="${HEXSTRIKE_MODE:-api}"
HEXSTRIKE_PORT="${HEXSTRIKE_PORT:-8888}"
HEXSTRIKE_SERVER_URL="${HEXSTRIKE_SERVER_URL:-http://127.0.0.1:${HEXSTRIKE_PORT}}"
HEXSTRIKE_STARTUP_TIMEOUT="${HEXSTRIKE_STARTUP_TIMEOUT:-60}"

debug_args=()
if [[ "${HEXSTRIKE_DEBUG:-0}" == "1" || "${HEXSTRIKE_DEBUG:-}" == "true" ]]; then
  debug_args+=(--debug)
fi

cd "${HEXSTRIKE_HOME}"

start_backend() {
  "${HEXSTRIKE_VENV}/bin/python" hexstrike_server.py --port "${HEXSTRIKE_PORT}" "${debug_args[@]}" >&2 &
  backend_pid=$!
}

wait_for_backend() {
  local waited=0
  until curl -fsS "${HEXSTRIKE_SERVER_URL}/health" >/dev/null 2>&1; do
    if (( waited >= HEXSTRIKE_STARTUP_TIMEOUT )); then
      echo "HexStrike backend did not become healthy at ${HEXSTRIKE_SERVER_URL}" >&2
      return 1
    fi
    waited=$((waited + 1))
    sleep 1
  done
}

case "${HEXSTRIKE_MODE}" in
  api|http|server)
    exec "${HEXSTRIKE_VENV}/bin/python" hexstrike_server.py --port "${HEXSTRIKE_PORT}" "${debug_args[@]}" "$@"
    ;;
  mcp|stdio)
    backend_pid=""
    cleanup() {
      if [[ -n "${backend_pid}" ]]; then
        kill "${backend_pid}" >/dev/null 2>&1 || true
        wait "${backend_pid}" >/dev/null 2>&1 || true
      fi
    }
    trap cleanup EXIT INT TERM

    if [[ "${HEXSTRIKE_START_BACKEND:-1}" == "1" ]]; then
      start_backend
      wait_for_backend
    fi

    "${HEXSTRIKE_VENV}/bin/python" hexstrike_mcp.py --server "${HEXSTRIKE_SERVER_URL}" "$@"
    ;;
  shell)
    exec /bin/bash "$@"
    ;;
  *)
    exec "$@"
    ;;
esac
