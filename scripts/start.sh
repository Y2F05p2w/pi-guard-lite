#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p run logs
source .venv/bin/activate

WEB_HOST="${PI_GUARD_WEB_HOST:-0.0.0.0}"
WEB_PORT="${PI_GUARD_WEB_PORT:-8080}"
PIPELINE_SOURCE="${PI_GUARD_PIPELINE_SOURCE:-suricata}"
PIPELINE_FILE="${PI_GUARD_PIPELINE_FILE:-/var/log/suricata/eve.json}"
PIPELINE_MODE="${PI_GUARD_PIPELINE_MODE:-tail}"
SCAN_ENABLED="${PI_GUARD_SCAN_ENABLED:-0}"
SCAN_BIND_HOST="${PI_GUARD_SCAN_BIND_HOST:-0.0.0.0}"
SCAN_REPORT_HOST="${PI_GUARD_SCAN_REPORT_HOST:-127.0.0.1}"
SCAN_PORTS="${PI_GUARD_SCAN_PORTS:-2201-2212}"

if [ -f run/web.pid ] && kill -0 "$(cat run/web.pid)" 2>/dev/null; then
  echo "[!] web service already running"
else
  nohup .venv/bin/uvicorn app.main:app --host "$WEB_HOST" --port "$WEB_PORT" > logs/web.out.log 2>&1 &
  echo $! > run/web.pid
  echo "[*] web service started"
fi

if [ -f run/pipeline.pid ] && kill -0 "$(cat run/pipeline.pid)" 2>/dev/null; then
  echo "[!] pipeline service already running"
else
  nohup .venv/bin/python scripts/run_pipeline_service.py \
    --source "$PIPELINE_SOURCE" \
    --file "$PIPELINE_FILE" \
    --mode "$PIPELINE_MODE" > logs/pipeline.out.log 2>&1 &
  echo $! > run/pipeline.pid
  echo "[*] pipeline service started"
fi

if [[ "$SCAN_ENABLED" == "1" ]]; then
  if [ -f run/scan_listener.pid ] && kill -0 "$(cat run/scan_listener.pid)" 2>/dev/null; then
    echo "[!] scan listener already running"
  else
    nohup .venv/bin/python scripts/run_scan_listener_service.py \
      --bind-host "$SCAN_BIND_HOST" \
      --report-host "$SCAN_REPORT_HOST" \
      --ports "$SCAN_PORTS" > logs/scan_listener.out.log 2>&1 &
    echo $! > run/scan_listener.pid
    echo "[*] scan listener service started"
  fi
else
  echo "[INFO] scan listener disabled (set PI_GUARD_SCAN_ENABLED=1 to enable)"
fi
