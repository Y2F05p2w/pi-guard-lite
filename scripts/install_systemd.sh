#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
TMP_DIR="$ROOT_DIR/run/systemd-rendered"

mkdir -p "$TMP_DIR"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  SUDO="sudo"
else
  SUDO=""
fi

render_unit() {
  local src="$1"
  local dst="$2"
  sed "s#/opt/pi-guard-lite#$ROOT_DIR#g" "$src" > "$dst"
}

echo "[*] rendering systemd units into $TMP_DIR"
for unit in "$ROOT_DIR"/systemd/*; do
  [[ -f "$unit" ]] || continue
  render_unit "$unit" "$TMP_DIR/$(basename "$unit")"
done

echo "[*] installing units into $SYSTEMD_DIR"
$SUDO mkdir -p "$SYSTEMD_DIR"
$SUDO cp "$TMP_DIR"/* "$SYSTEMD_DIR"/

echo "[*] reloading systemd"
$SUDO systemctl daemon-reload

echo "[*] enabling core services"
$SUDO systemctl enable pi-guard-lite.service
$SUDO systemctl enable pi-guard-lite-pipeline.service
$SUDO systemctl enable pi-guard-lite-input-supervisor.service || true
$SUDO systemctl enable pi-guard-lite-release-expired.timer

echo "[*] optional service (enable manually if needed): pi-guard-lite-fluentbit.service"
echo "[*] installed units:"
ls -1 "$TMP_DIR"
