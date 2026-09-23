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
install -m 0644 "$SRC_DIR/ssh_server.py" "$PREFIX/ssh_server.py"

if compgen -G "$SRC_DIR/presets/*.json" > /dev/null; then
    install -m 0644 "$SRC_DIR"/presets/*.json "$PREFIX/presets/"
fi

echo "==> Installing CLI wrapper at $BIN_LINK"
ln -sf "$PREFIX/mimic.py" "$BIN_LINK"

echo "==> Checking asyncssh (needed for full SSH handshake)"
if ! python3 -c "import asyncssh" 2>/dev/null; then
    echo "    asyncssh not found, installing..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get install -y python3-asyncssh
    else
        pip3 install asyncssh
    fi
else
    echo "    asyncssh already installed"
fi

echo "==> Generating SSH host keys (if missing)"
if [[ ! -f "$PREFIX/ssh_host_ed25519_key" ]]; then
    ssh-keygen -t ed25519 -f "$PREFIX/ssh_host_ed25519_key" -N "" -q
    echo "    generated ed25519 key"
fi
if [[ ! -f "$PREFIX/ssh_host_rsa_key" ]]; then
    ssh-keygen -t rsa -b 4096 -f "$PREFIX/ssh_host_rsa_key" -N "" -q
    echo "    generated rsa key"
fi

chown root:nogroup "$PREFIX"/ssh_host_*_key*
chmod 640 "$PREFIX"/ssh_host_*_key
chmod 644 "$PREFIX"/ssh_host_*_key.pub

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
    [[ -f "$src_chain" && -f "$src_key" ]] || continue

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

[[ $FOUND -eq 0 ]] && echo "    no certificates found; skipping"

# --- Install certbot deploy hook ---
if [[ -d /etc/letsencrypt/renewal-hooks/deploy ]]; then
    echo "==> Installing certbot deploy hook"
    install -m 0755 \
        "$SRC_DIR/scripts/mimic-copy-certs.sh" \
        /etc/letsencrypt/renewal-hooks/deploy/mimic-copy-certs.sh
fi

echo
echo "Done. Next steps:"
echo "  1. Edit $CONFIG_DIR/config.json"
echo "  2. systemctl enable --now mimic"
echo "  3. journalctl -u mimic -f"
echo
echo "CLI available as: mimic --help"