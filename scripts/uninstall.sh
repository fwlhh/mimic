#!/usr/bin/env bash
# Stop and remove Mimic.
#
# By default removes:
#   - systemd unit
#   - /opt/mimic/
#   - /etc/mimic/
#   - CLI symlink
#   - certbot deploy hook
#
# Optionally removes (prompted):
#   - pip package asyncssh
#
# Environment overrides:
#   PREFIX=/opt/mimic
#   CONFIG_DIR=/etc/mimic
#   BIN_LINK=/usr/local/bin/mimic
#   PURGE_DEPS=1     # remove dependencies without prompting
#   KEEP_DEPS=1      # keep dependencies without prompting
set -euo pipefail

PREFIX="${PREFIX:-/opt/mimic}"
CONFIG_DIR="${CONFIG_DIR:-/etc/mimic}"
BIN_LINK="${BIN_LINK:-/usr/local/bin/mimic}"
CERTBOT_HOOK="/etc/letsencrypt/renewal-hooks/deploy/mimic-copy-certs.sh"

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

echo "==> Removing CLI wrapper"
rm -f "$BIN_LINK"

echo "==> Removing certbot deploy hook"
rm -f "$CERTBOT_HOOK"

# --- Data directories ---------------------------------------------------
echo
read -rp "Remove $PREFIX and $CONFIG_DIR? [y/N] " ans
if [[ "${ans,,}" == "y" ]]; then
    rm -rf "$PREFIX" "$CONFIG_DIR"
    echo "    removed."
else
    echo "    kept."
fi

# --- Optional dependencies ---------------------------------------------
if [[ "${PURGE_DEPS:-0}" == "1" ]]; then
    purge_deps=1
elif [[ "${KEEP_DEPS:-0}" == "1" ]]; then
    purge_deps=0
else
    echo
    echo "Mimic installed asyncssh system-wide via pip."
    echo "WARNING: other software may depend on it."
    read -rp "Remove asyncssh too? [y/N] " ans
    if [[ "${ans,,}" == "y" ]]; then
        purge_deps=1
    else
        purge_deps=0
    fi
fi

if [[ "$purge_deps" == "1" ]]; then
    echo "==> Removing pip package asyncssh"
    pip3 uninstall -y --break-system-packages asyncssh 2>/dev/null || true
    echo "    removed."
else
    echo "    dependencies kept."
fi

echo
echo "Uninstalled."