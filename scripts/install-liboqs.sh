#!/usr/bin/env bash
# Build and install liboqs + liboqs-python.
#
# liboqs enables the post-quantum KEX
# sntrup761x25519-sha512@openssh.com in asyncssh, which is what real
# OpenSSH 9.6p1 on Ubuntu 24.04 advertises.
#
# Idempotent: exits early if liboqs is already installed.
set -euo pipefail

LIBOQS_VERSION="${LIBOQS_VERSION:-0.11.0}"
LIBOQS_SRC="${LIBOQS_SRC:-/usr/local/src/liboqs}"

if ldconfig -p 2>/dev/null | grep -q liboqs; then
    echo "    liboqs already installed, skipping build"
else
    echo "    installing build dependencies..."
    apt-get install -y --no-install-recommends \
        cmake ninja-build gcc g++ libssl-dev \
        python3-pytest python3-pytest-xdist python3-yaml \
        unzip xsltproc doxygen graphviz valgrind git

    echo "    cloning liboqs ${LIBOQS_VERSION}..."
    rm -rf "$LIBOQS_SRC"
    git clone --depth=1 --branch "$LIBOQS_VERSION" \
        https://github.com/open-quantum-safe/liboqs.git "$LIBOQS_SRC"

    echo "    building liboqs..."
    mkdir -p "$LIBOQS_SRC/build"
    cd "$LIBOQS_SRC/build"
    cmake -GNinja \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DOQS_USE_OPENSSL=ON \
        -DBUILD_SHARED_LIBS=ON \
        ..
    ninja
    ninja install
    ldconfig
    echo "    liboqs installed to /usr/local"
fi

# --- liboqs-python -----------------------------------------------------
echo "    installing liboqs-python..."
pip3 install --upgrade --break-system-packages --ignore-installed \
    liboqs-python

# --- verify ------------------------------------------------------------
echo "    verifying sntrup761 availability..."
if python3 -c "from asyncssh.kex import get_kex_algs; import sys; sys.exit(0 if 'sntrup761x25519-sha512@openssh.com' in get_kex_algs() else 1)" 2>/dev/null; then
    echo "    OK: sntrup761x25519-sha512@openssh.com is available"
else
    echo "    WARNING: sntrup761 is still unavailable after liboqs install"
    echo "    Mimic will start without post-quantum KEX."
fi

exit 0