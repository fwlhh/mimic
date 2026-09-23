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
#   - pip packages asyncssh, liboqs-python
#   - liboqs library and headers
#   - liboqs source tree
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
LIBOQS_SRC="${LIBOQS_SRC:-/usr/local/src/liboqs}"
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
# Determine whether to purge deps.
if [[ "${PURGE_DEPS:-0}" == "1" ]]; then
    purge_deps=1
elif [[ "${KEEP_DEPS:-0}" == "1" ]]; then
    purge_deps=0
else
    echo
    echo "Mimic installed the following system-wide packages:"
    echo "  - pip: asyncssh, liboqs-python"
    echo "  - system: liboqs (in /usr/local/lib, /usr/local/include)"
    echo "  - source: $LIBOQS_SRC"
    echo
    echo "WARNING: other software may depend on these."
    read -rp "Remove them too? [y/N] " ans
    if [[ "${ans,,}" == "y" ]]; then
        purge_deps=1
    else
        purge_deps=0
    fi
fi

if [[ "$purge_deps" == "1" ]]; then
    echo "==> Removing pip packages"
    pip3 uninstall -y --break-system-packages asyncssh 2>/dev/null || true
    pip3 uninstall -y --break-system-packages liboqs-python 2>/dev/null || true

    echo "==> Removing liboqs library and headers"
    # Files installed by `ninja install` into /usr/local.
    rm -f /usr/local/lib/liboqs.so*
    rm -f /usr/local/lib/pkgconfig/liboqs.pc
    rm -rf /usr/local/include/oqs
    rm -rf /usr/local/lib/cmake/liboqs
    ldconfig

    echo "==> Removing liboqs source tree"
    rm -rf "$LIBOQS_SRC"

    echo "    dependencies removed."
else
    echo "    dependencies kept."
fi

echo
echo "Uninstalled."