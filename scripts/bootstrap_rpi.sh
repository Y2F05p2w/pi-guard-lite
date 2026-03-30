#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "[!] please run as root: sudo bash scripts/bootstrap_rpi.sh"
  exit 1
fi

INSTALL_FLUENTBIT="${INSTALL_FLUENTBIT:-0}"
INSTALL_SURICATA="${INSTALL_SURICATA:-0}"

echo "[*] updating apt metadata"
apt-get update

echo "[*] installing base runtime packages"
apt-get install -y \
  git \
  curl \
  rsync \
  sqlite3 \
  python3 \
  python3-pip \
  python3-venv \
  build-essential

if [[ "$INSTALL_FLUENTBIT" == "1" ]]; then
  echo "[*] installing fluent-bit"
  apt-get install -y fluent-bit || true
fi

if [[ "$INSTALL_SURICATA" == "1" ]]; then
  echo "[*] installing suricata"
  apt-get install -y suricata || true
fi

echo "[*] bootstrap finished"
echo "    next steps:"
echo "    1. git clone project into /opt/pi-guard-lite"
echo "    2. bash scripts/install.sh"
echo "    3. bash scripts/install_systemd.sh"
