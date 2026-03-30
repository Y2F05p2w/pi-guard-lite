#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p backups
STAMP="$(date +%Y%m%d-%H%M%S)"
ARCHIVE="backups/pi-guard-lite-${STAMP}.tar.gz"

tar -czf "$ARCHIVE" \
  config \
  data \
  docs \
  models \
  logs \
  systemd \
  README.md \
  requirements.txt

echo "[*] backup created: $ARCHIVE"
