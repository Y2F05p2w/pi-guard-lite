#!/usr/bin/env bash
set -euo pipefail

check_service() {
  local name="$1"
  if command -v systemctl >/dev/null 2>&1; then
    local state
    state="$(systemctl is-active "$name" 2>/dev/null || true)"
    echo "${name}: ${state:-unknown}"
  else
    echo "${name}: systemctl-unavailable"
  fi
}

echo "== Pi-Guard Lite service status =="
check_service "pi-guard-lite.service"
check_service "pi-guard-lite-pipeline.service"
check_service "pi-guard-lite-fluentbit.service"
check_service "pi-guard-lite-release-expired.timer"

if command -v curl >/dev/null 2>&1; then
  echo
  echo "== health endpoint =="
  curl -fsS http://127.0.0.1:8080/health || echo "[WARN] health endpoint unavailable"
  echo
fi
