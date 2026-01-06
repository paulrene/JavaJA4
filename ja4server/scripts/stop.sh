#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RUN_DIR="$ROOT_DIR/run"
PID_FILE="$RUN_DIR/ja4-server.pid"

if [[ ! -f "$PID_FILE" ]]; then
  echo "No PID file found."
  exit 0
fi

PID=$(cat "$PID_FILE")
if kill -0 "$PID" >/dev/null 2>&1; then
  kill "$PID"
  for _ in {1..20}; do
    if kill -0 "$PID" >/dev/null 2>&1; then
      sleep 0.5
    else
      break
    fi
  done
fi

rm -f "$PID_FILE"

echo "Stopped JA4 server."
