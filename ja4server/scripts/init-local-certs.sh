#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
JAR_PATH="$ROOT_DIR/target/ja4-server.jar"

if [[ ! -f "$JAR_PATH" ]]; then
  mvn -q -DskipTests package
fi

java -cp "$JAR_PATH" no.hux.ja4.CertGenerator --out-dir "$ROOT_DIR/certs/local" "$@"
