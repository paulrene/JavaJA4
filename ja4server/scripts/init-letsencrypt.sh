#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <domain> <email> [certbot-args...]"
  exit 1
fi

DOMAIN=$1
EMAIL=$2
shift 2

sudo certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos -m "$EMAIL" "$@"
