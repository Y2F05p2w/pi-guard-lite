#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

FLUENT_BIT_BIN="${FLUENT_BIT_BIN:-fluent-bit}"
FLUENT_BIT_CONF="${FLUENT_BIT_CONF:-$ROOT_DIR/config/fluent-bit.conf}"

source .venv/bin/activate

exec "$FLUENT_BIT_BIN" -c "$FLUENT_BIT_CONF" | .venv/bin/python scripts/run_fluentbit_stdin.py
