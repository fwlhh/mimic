#!/usr/bin/env bash
# Stop and remove Mimic. Prompts before deleting data directories.
set -euo pipefail

PREFIX="${PREFIX:-/opt/mimic}"
CONFIG_DIR="${CONFIG_DIR:-/etc/mimic}"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

echo "==> Stopping service"
systemctl stop mimic 2>/dev/null || true
systemctl disable mimic 2>/dev/null || true

echo "==> Removing systemd unit"
rm -f /etc/systemd/system/mimic.service
systemctl daemon-reload

read -rp "Remove $PREFIX and $CONFIG_DIR? [y/N] " ans
if [[ "${ans,,}" == "y" ]]; then
    rm -rf "$PREFIX" "$CONFIG_DIR"
    echo "    removed."
else
    echo "    kept."
fi

echo "Uninstalled."