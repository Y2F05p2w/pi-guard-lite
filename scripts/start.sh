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
