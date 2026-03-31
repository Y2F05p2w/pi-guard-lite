#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "== Pi-Guard Lite local pid status =="
for name in web pipeline scan_listener; do
  pid_file="run/${name}.pid"
  if [[ -f "$pid_file" ]]; then
    pid="$(cat "$pid_file")"
    if kill -0 "$pid" 2>/dev/null; then
      echo "[OK] ${name}: running pid=${pid}"
    else
      echo "[WARN] ${name}: stale pid file (${pid})"
    fi
  else
    echo "[INFO] ${name}: not started with scripts/start.sh"
  fi
done

if command -v systemctl >/dev/null 2>&1; then
  echo
  echo "== systemd services =="
  for service in \
    pi-guard-lite.service \
    pi-guard-lite-pipeline.service \
    pi-guard-lite-scan-listener.service \
    pi-guard-lite-fluentbit.service \
    pi-guard-lite-release-expired.timer
  do
    state="$(systemctl is-active "$service" 2>/dev/null || true)"
    echo "${service}: ${state:-unknown}"
  done
fi

if command -v curl >/dev/null 2>&1; then
  echo
  echo "== health check =="
  curl -fsS http://127.0.0.1:8080/health || echo "[WARN] health endpoint unavailable"
  echo
fi
