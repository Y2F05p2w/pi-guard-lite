#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

ARCHIVE="${1:-}"
if [[ -z "$ARCHIVE" ]]; then
  echo "usage: bash scripts/restore.sh <backup.tar.gz>"
  exit 1
fi

if [[ ! -f "$ARCHIVE" ]]; then
  echo "[!] archive not found: $ARCHIVE"
  exit 1
fi

if [[ "${PI_GUARD_RESTORE_CONFIRM:-}" != "YES" ]]; then
  echo "[!] set PI_GUARD_RESTORE_CONFIRM=YES to allow restore"
  exit 1
fi

tar -xzf "$ARCHIVE" -C "$ROOT_DIR"
echo "[*] restore complete from: $ARCHIVE"
