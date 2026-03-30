#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

stop_pid_file() {
  local name="$1"
  local file="run/${name}.pid"
  if [ -f "$file" ]; then
    local pid
    pid="$(cat "$file")"
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid"
      echo "[*] stopped ${name} (${pid})"
    fi
    rm -f "$file"
  else
    echo "[!] ${name} not running"
  fi
}

stop_pid_file "pipeline"
stop_pid_file "web"
