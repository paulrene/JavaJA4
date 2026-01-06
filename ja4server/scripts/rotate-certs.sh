#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ARGS_FILE="$ROOT_DIR/run/ja4-server.args"

if ! command -v certbot >/dev/null 2>&1; then
  echo "certbot not found."
  exit 1
fi

sudo certbot renew --quiet

if [[ -f "$ARGS_FILE" ]]; then
  mapfile -t ARGS < "$ARGS_FILE"
  "$ROOT_DIR/scripts/stop.sh"
  "$ROOT_DIR/scripts/start.sh" "${ARGS[@]}"
else
  echo "No args file found; restart skipped."
fi
