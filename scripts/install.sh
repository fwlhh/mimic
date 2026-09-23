#!/usr/bin/env bash
# Install Mimic to /opt/mimic with systemd unit and default config.
set -euo pipefail

PREFIX="${PREFIX:-/opt/mimic}"
CONFIG_DIR="${CONFIG_DIR:-/etc/mimic}"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$(dirname "$SCRIPT_DIR")"

echo "==> Installing to $PREFIX"
install -d "$PREFIX"
install -d "$PREFIX/presets"

install -m 0755 "$SRC_DIR/mimic.py"      "$PREFIX/mimic.py"
install -m 0644 "$SRC_DIR/signatures.py" "$PREFIX/signatures.py"

if compgen -G "$SRC_DIR/presets/*.json" > /dev/null; then
    install -m 0644 "$SRC_DIR"/presets/*.json "$PREFIX/presets/"
fi

echo "==> Creating config directory $CONFIG_DIR"
install -d -m 0755 "$CONFIG_DIR"
if [[ ! -f "$CONFIG_DIR/config.json" ]]; then
    install -m 0644 "$SRC_DIR/config.example.json" "$CONFIG_DIR/config.json"
    echo "    wrote $CONFIG_DIR/config.json (edit it before starting)"
fi

echo "==> Installing systemd unit"
install -m 0644 "$SRC_DIR/systemd/mimic.service" /etc/systemd/system/mimic.service
systemctl daemon-reload

echo
echo "Done. Next steps:"
echo "  1. Edit $CONFIG_DIR/config.json"
echo "  2. systemctl enable --now mimic"
echo "  3. journalctl -u mimic -f"