#!/usr/bin/env bash
# Install Mimic to /opt/mimic with systemd unit and default config.
set -euo pipefail

PREFIX="${PREFIX:-/opt/mimic}"
CONFIG_DIR="${CONFIG_DIR:-/etc/mimic}"
CERT_DIR="${CERT_DIR:-/opt/mimic/certs}"
LETSENCRYPT_LIVE="${LETSENCRYPT_LIVE:-/etc/letsencrypt/live}"
BIN_LINK="${BIN_LINK:-/usr/local/bin/mimic}"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$(dirname "$SCRIPT_DIR")"

echo "==> Installing to $PREFIX"
install -d "$PREFIX"
install -d "$PREFIX/presets"
install -d "$CERT_DIR"

install -m 0755 "$SRC_DIR/mimic.py"      "$PREFIX/mimic.py"
install -m 0644 "$SRC_DIR/signatures.py" "$PREFIX/signatures.py"

if compgen -G "$SRC_DIR/presets/*.json" > /dev/null; then
    install -m 0644 "$SRC_DIR"/presets/*.json "$PREFIX/presets/"
fi

echo "==> Installing CLI wrapper at $BIN_LINK"
ln -sf "$PREFIX/mimic.py" "$BIN_LINK"

echo "==> Creating config directory $CONFIG_DIR"
install -d -m 0755 "$CONFIG_DIR"
if [[ ! -f "$CONFIG_DIR/config.json" ]]; then
    install -m 0644 "$SRC_DIR/config.example.json" "$CONFIG_DIR/config.json"
    echo "    wrote $CONFIG_DIR/config.json (edit it before starting)"
fi
chown root:nogroup "$CONFIG_DIR/config.json"
chmod 640 "$CONFIG_DIR/config.json"

echo "==> Installing systemd unit"
install -m 0644 "$SRC_DIR/systemd/mimic.service" \
        /etc/systemd/system/mimic.service
systemctl daemon-reload

# --- Copy existing certificates, one subdirectory per domain ---
echo "==> Looking for certificates in $LETSENCRYPT_LIVE"
shopt -s nullglob
FOUND=0
for lineage in "$LETSENCRYPT_LIVE"/*/; do
    domain="$(basename "$lineage")"
    src_chain="$lineage/fullchain.pem"
    src_key="$lineage/privkey.pem"

    if [[ ! -f "$src_chain" || ! -f "$src_key" ]]; then
        continue
    fi

    dst_dir="$CERT_DIR/$domain"
    install -d -m 0750 -o root -g nogroup "$dst_dir"

    cp "$src_chain" "$dst_dir/fullchain.pem"
    cp "$src_key"   "$dst_dir/privkey.pem"

    chown root:nogroup "$dst_dir/fullchain.pem" "$dst_dir/privkey.pem"
    chmod 644 "$dst_dir/fullchain.pem"
    chmod 640 "$dst_dir/privkey.pem"

    echo "    copied $domain -> $dst_dir"
    FOUND=$((FOUND + 1))
done
shopt -u nullglob

if [[ $FOUND -eq 0 ]]; then
    echo "    no certificates found; skipping"
    echo "    (add TLS certs later to $CERT_DIR/<domain>/)"
else
    echo "    copied $FOUND domain(s)"
fi

# --- Install certbot deploy hook ---
if [[ -d /etc/letsencrypt/renewal-hooks/deploy ]]; then
    echo "==> Installing certbot deploy hook"
    install -m 0755 \
        "$SRC_DIR/scripts/mimic-copy-certs.sh" \
        /etc/letsencrypt/renewal-hooks/deploy/mimic-copy-certs.sh
else
    echo "==> certbot not installed; skipping deploy hook"
fi

echo
echo "Done. Next steps:"
echo "  1. Edit $CONFIG_DIR/config.json"
echo "  2. systemctl enable --now mimic"
echo "  3. journalctl -u mimic -f"
echo
echo "CLI available as: mimic --help"