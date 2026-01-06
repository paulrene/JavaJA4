#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
JAR_PATH="$ROOT_DIR/target/ja4-server.jar"
LOG_DIR="$ROOT_DIR/logs"
RUN_DIR="$ROOT_DIR/run"
PID_FILE="$RUN_DIR/ja4-server.pid"
ARGS_FILE="$RUN_DIR/ja4-server.args"

mkdir -p "$LOG_DIR" "$RUN_DIR"

if [[ -f "$PID_FILE" ]]; then
  PID=$(cat "$PID_FILE")
  if kill -0 "$PID" >/dev/null 2>&1; then
    echo "Server already running (PID $PID)."
    exit 1
  fi
fi

if [[ ! -f "$JAR_PATH" ]]; then
  mvn -q -DskipTests package
fi

JAVA_OPTS=${JAVA_OPTS:-""}

nohup java $JAVA_OPTS -jar "$JAR_PATH" "$@" > "$LOG_DIR/ja4-server.log" 2>&1 &
PID=$!

echo "$PID" > "$PID_FILE"
printf '%s\n' "$@" > "$ARGS_FILE"

echo "Started JA4 server (PID $PID)."
