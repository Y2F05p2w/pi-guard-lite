#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python3}"

echo "[*] creating virtual environment"
"$PYTHON_BIN" -m venv .venv
source .venv/bin/activate

echo "[*] upgrading pip"
python -m pip install --upgrade pip

echo "[*] installing requirements"
pip install -r requirements.txt

echo "[*] ensuring runtime directories"
mkdir -p data/raw logs backups models/imported

echo "[*] creating demo models"
python scripts/create_demo_models.py

echo "[*] initializing database"
python - <<'PY'
from app.common.db import init_db
init_db()
print("database initialized")
PY

echo "[*] installation completed"
