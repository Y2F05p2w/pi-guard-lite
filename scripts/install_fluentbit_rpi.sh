#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_CONF="$ROOT_DIR/config/fluent-bit-rpi.conf"
TARGET_CONF="${TARGET_CONF:-/etc/fluent-bit/fluent-bit.conf}"
TARGET_DIR="$(dirname "$TARGET_CONF")"
STATE_DIR="${STATE_DIR:-$ROOT_DIR/data/fluent-bit}"

if [[ ! -f "$SOURCE_CONF" ]]; then
  echo "[!] missing source config: $SOURCE_CONF"
  exit 1
fi

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  SUDO="sudo"
else
  SUDO=""
fi

echo "[*] ensuring target directories"
$SUDO mkdir -p "$TARGET_DIR"
$SUDO mkdir -p "$STATE_DIR"

echo "[*] installing Fluent Bit config"
$SUDO cp "$SOURCE_CONF" "$TARGET_CONF"

echo "[*] installed: $TARGET_CONF"
echo "[*] state dir: $STATE_DIR"
echo "[*] you can now enable pi-guard-lite-fluentbit.service"
